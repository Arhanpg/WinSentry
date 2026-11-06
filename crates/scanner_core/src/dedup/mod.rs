//! Two-Stage Cryptographic Deduplication Engine
//!
//! Multi-stage elimination funnel:
//! 1. Minimum size floor (default 8 KB CLI / 16 KB GUI)
//! 2. Group by exact byte size (zero disk reads)
//! 3. Two-stage edge-chunk prehashing (start + end 4 KB chunk read)
//! 4. Full multithreaded Blake3 hashing
//! 5. Concurrent SHA-256 calculation for threat intelligence
//! 6. Perceptual image hashing and Reference Folder protection

pub mod perceptual;

use crate::models::{DuplicateGroup, ScannedFile};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Edge chunk read size for prehashing (4 KB)
const PREHASH_CHUNK_SIZE: usize = 4096;

/// Reads up to 4 KB from start and up to 4 KB from end, hashing the combined sample
pub fn compute_edge_prehash<P: AsRef<Path>>(path: P, file_size: u64) -> Option<String> {
    if file_size == 0 {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();

    let mut start_chunk = vec![0u8; PREHASH_CHUNK_SIZE.min(file_size as usize)];
    file.read_exact(&mut start_chunk).ok()?;
    hasher.update(&start_chunk);

    if file_size > PREHASH_CHUNK_SIZE as u64 {
        let end_read_size = PREHASH_CHUNK_SIZE.min((file_size - start_chunk.len() as u64) as usize);
        if end_read_size > 0 {
            let offset = file_size - end_read_size as u64;
            file.seek(SeekFrom::Start(offset)).ok()?;
            let mut end_chunk = vec![0u8; end_read_size];
            file.read_exact(&mut end_chunk).ok()?;
            hasher.update(&end_chunk);
        }
    }

    Some(hasher.finalize().to_hex().to_string())
}

/// Computes both full Blake3 digest and SHA-256 digest in a single streaming pass
pub fn compute_full_hashes<P: AsRef<Path>>(path: P) -> Option<(String, String)> {
    let mut file = File::open(path).ok()?;
    let mut blake_hasher = blake3::Hasher::new();
    let mut sha_hasher = Sha256::new();

    let mut buffer = vec![0u8; 64 * 1024]; // 64 KB read buffer
    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        let chunk = &buffer[..bytes_read];
        blake_hasher.update(chunk);
        sha_hasher.update(chunk);
    }

    let blake_str = blake_hasher.finalize().to_hex().to_string();
    let sha_str = hex::encode(sha_hasher.finalize());
    Some((blake_str, sha_str))
}

/// Executes the two-stage deduplication pipeline over scanned files
pub fn find_duplicates(
    files: &mut [ScannedFile],
    minimal_file_size: u64,
    reference_folders: &[std::path::PathBuf],
) -> Vec<DuplicateGroup> {
    // 0. Mark Reference Folders
    for file in files.iter_mut() {
        for ref_dir in reference_folders {
            if file.path.starts_with(ref_dir) {
                file.is_in_reference_folder = true;
                break;
            }
        }
    }

    // 1. Filter by minimum size floor and ignore directories or cloud placeholders
    let eligible_indices: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            !f.is_directory
                && !f.is_cloud_placeholder
                && f.logical_size >= minimal_file_size
        })
        .map(|(idx, _)| idx)
        .collect();

    // 2. Group by exact file size
    let mut size_buckets: HashMap<u64, Vec<usize>> = HashMap::new();
    for &idx in &eligible_indices {
        let size = files[idx].logical_size;
        size_buckets.entry(size).or_default().push(idx);
    }

    // Filter out sizes with only 1 file
    let candidate_sizes: Vec<Vec<usize>> = size_buckets
        .into_values()
        .filter(|indices| indices.len() > 1)
        .collect();

    // 3. Stage 1: Prehashing (start + end chunk) in parallel
    let prehashed_candidates: Vec<Vec<usize>> = candidate_sizes
        .into_par_iter()
        .flat_map_iter(|indices| {
            let mut prehash_map: HashMap<String, Vec<usize>> = HashMap::new();
            for idx in indices {
                let size = files[idx].logical_size;
                let path = &files[idx].path;
                if let Some(hash) = compute_edge_prehash(path, size) {
                    prehash_map.entry(hash).or_default().push(idx);
                }
            }
            let valid: Vec<Vec<usize>> = prehash_map.into_values().filter(|v| v.len() > 1).collect();
            valid
        })
        .collect();

    // 4. Stage 2: Full Blake3 and SHA-256 Hashing in parallel
    let full_hash_groups: Vec<(String, u64, Vec<usize>)> = prehashed_candidates
        .into_par_iter()
        .flat_map_iter(|indices| {
            let mut hash_map: HashMap<String, (u64, Vec<usize>)> = HashMap::new();
            for idx in indices {
                let path = &files[idx].path;
                let size = files[idx].logical_size;
                if let Some((b3, _sha)) = compute_full_hashes(path) {
                    hash_map
                        .entry(b3)
                        .or_insert_with(|| (size, Vec::new()))
                        .1
                        .push(idx);
                }
            }
            let valid: Vec<(String, u64, Vec<usize>)> = hash_map
                .into_iter()
                .filter(|(_, (_, v))| v.len() > 1)
                .map(|(b3, (size, v))| (b3, size, v))
                .collect();
            valid
        })
        .collect();

    // 5. Construct DuplicateGroup models
    let mut duplicate_groups = Vec::new();
    for (b3, file_size, indices) in full_hash_groups {
        let mut group_files = Vec::new();
        for &idx in &indices {
            // Update hash in ScannedFile
            files[idx].blake3_hash = Some(b3.clone());
            group_files.push(files[idx].clone());
        }

        let count = group_files.len() as u64;
        let reclaimable = if count > 1 {
            (count - 1) * file_size
        } else {
            0
        };

        duplicate_groups.push(DuplicateGroup {
            file_size,
            blake3_hash: b3,
            reclaimable_bytes: reclaimable,
            files: group_files,
        });
    }

    duplicate_groups.sort_by(|a, b| b.reclaimable_bytes.cmp(&a.reclaimable_bytes));
    duplicate_groups
}
