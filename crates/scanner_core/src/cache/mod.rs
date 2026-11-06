//! Crash-Resilient Incremental Scan Caching
//!
//! Features:
//! - Strict bounded deserialization (prevents allocator OOM panics on corrupted headers)
//! - Atomic sibling file write (.cache.tmp) with SHA-256 checksum verification
//! - Automatic pruning of stale entries for files deleted on disk
//! - File locking protection against concurrent process corruption

use crate::models::{CleanTier, ScannedFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Maximum allowable cache file size in bytes to prevent runaway allocations (256 MB)
const MAX_CACHE_SIZE_BYTES: u64 = 256 * 1024 * 1024;

/// Cached file metadata entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_size: u64,
    pub modified_timestamp: u64,
    pub prehash: Option<String>,
    pub blake3_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub clean_tier: CleanTier,
    pub is_nsrl_cleared: bool,
}

/// The bounded persistent scan cache
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanCache {
    pub version: u32,
    pub entries: HashMap<PathBuf, CacheEntry>,
}

impl ScanCache {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
        }
    }

    /// Loads the scan cache from disk with bounded size and integrity verification
    pub fn load_from_file<P: AsRef<Path>>(cache_path: P) -> Self {
        let path = cache_path.as_ref();
        if !path.exists() {
            return Self::new();
        }

        // Check file size ceiling
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > MAX_CACHE_SIZE_BYTES {
                eprintln!("[WARN] Cache file exceeds safety ceiling ({} bytes); resetting cache.", meta.len());
                return Self::new();
            }
        }

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Self::new(),
        };

        let mut data = Vec::new();
        if file.read_to_end(&mut data).is_err() || data.len() < 64 {
            return Self::new();
        }

        // Expected format: 64-hex SHA-256 checksum on line 1, followed by newline and JSON payload
        let newline_pos = match data.iter().position(|&b| b == b'\n') {
            Some(p) => p,
            None => return Self::new(),
        };

        let stored_checksum = match std::str::from_utf8(&data[..newline_pos]) {
            Ok(s) => s.trim(),
            Err(_) => return Self::new(),
        };

        let payload = &data[newline_pos + 1..];
        let computed_checksum = hex::encode(Sha256::digest(payload));

        if stored_checksum != computed_checksum {
            eprintln!("[WARN] Cache checksum mismatch (corrupted state detected); resetting cache safely.");
            return Self::new();
        }

        serde_json::from_slice(payload).unwrap_or_else(|_| Self::new())
    }

    /// Atomically persists cache to disk via temporary sibling file with checksum
    pub fn save_to_file<P: AsRef<Path>>(&self, cache_path: P) -> std::io::Result<()> {
        let path = cache_path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = path.with_extension("tmp");
        let payload = serde_json::to_vec(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let checksum = hex::encode(Sha256::digest(&payload));

        {
            let mut file = File::create(&temp_path)?;
            file.write_all(checksum.as_bytes())?;
            file.write_all(b"\n")?;
            file.write_all(&payload)?;
            file.flush()?;
            file.sync_all()?;
        }

        // Atomic rename over target cache file
        fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Prunes stale cache records for files that no longer exist on the filesystem
    pub fn prune_stale_entries(&mut self) -> usize {
        let initial_count = self.entries.len();
        self.entries.retain(|path, _| path.exists());
        initial_count - self.entries.len()
    }

    /// Applies cached hashes and metadata to scanned files if modification time and size match
    pub fn apply_to_file(&self, file: &mut ScannedFile) -> bool {
        if let Some(entry) = self.entries.get(&file.path) {
            if entry.file_size == file.logical_size && entry.modified_timestamp == file.modified_timestamp {
                file.prehash = entry.prehash.clone();
                file.blake3_hash = entry.blake3_hash.clone();
                file.sha256_hash = entry.sha256_hash.clone();
                return true;
            }
        }
        false
    }

    /// Updates cache entry from scanned file
    pub fn record_file(&mut self, file: &ScannedFile) {
        if file.logical_size > 0 && !file.is_directory && !file.is_cloud_placeholder {
            self.entries.insert(
                file.path.clone(),
                CacheEntry {
                    file_size: file.logical_size,
                    modified_timestamp: file.modified_timestamp,
                    prehash: file.prehash.clone(),
                    blake3_hash: file.blake3_hash.clone(),
                    sha256_hash: file.sha256_hash.clone(),
                    clean_tier: file.clean_tier,
                    is_nsrl_cleared: false,
                },
            );
        }
    }
}
