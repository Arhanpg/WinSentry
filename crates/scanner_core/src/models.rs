//! WinSentry Core Data Models
//!
//! Strongly-typed representation of file metadata, storage metrics,
//! security findings, and remediation action plans.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deterministic action tiers for space reclamation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CleanTier {
    /// Safe deterministic purge: package manager caches, shader caches, crash dumps, empty files/dirs
    Safe,
    /// Contextual audit: extracted archives, build trees (target, node_modules), dormant cold storage
    Review,
    /// Elevated system check: Volume Shadow Copies
    Advisory,
    /// Normal active file
    Active,
}

impl CleanTier {
    pub fn label(&self) -> &'static str {
        match self {
            CleanTier::Safe => "[SAFE]",
            CleanTier::Review => "[REVIEW]",
            CleanTier::Advisory => "[ADVISORY]",
            CleanTier::Active => "[ACTIVE]",
        }
    }
}

/// Security vulnerability category
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A specific security or vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: SecuritySeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub remediation_advice: String,
}

/// Complete telemetry and audit metadata for a scanned file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedFile {
    /// Normalized full file path
    pub path: PathBuf,
    /// User-friendly display path (without \\?\ prefix)
    pub display_path: String,
    /// File name
    pub file_name: String,
    /// Extension in lower-case without dot
    pub extension: String,
    /// Logical size in bytes
    pub logical_size: u64,
    /// Ground-truth physical size on disk (NTFS cluster allocation)
    pub physical_size: u64,
    /// Raw Win32 file attributes
    pub attributes: u32,
    /// Whether this is a directory
    pub is_directory: bool,
    /// Whether this file is a reparse point (symlink, junction, mount point)
    pub is_reparse_point: bool,
    /// Whether the symlink or junction target is broken / missing
    pub is_broken_link: bool,
    /// Reparse tag (e.g. IO_REPARSE_TAG_SYMLINK)
    pub reparse_tag: u32,
    /// Whether this is an un-hydrated cloud placeholder (OneDrive/iCloud)
    pub is_cloud_placeholder: bool,
    /// Whether the file has Alternate Data Streams
    pub has_alternate_data_streams: bool,
    /// Secondary Alternate Data Stream names and sizes
    pub alternate_data_streams: Vec<(String, u64)>,
    /// Last write time (Unix timestamp in seconds)
    pub modified_timestamp: u64,
    /// Days since last modification
    pub age_days: u32,
    /// Prehash (32-byte hash of start + end 4KB chunks)
    pub prehash: Option<String>,
    /// Full Blake3 cryptographic digest
    pub blake3_hash: Option<String>,
    /// SHA-256 digest (computed for binaries/scripts and threat intelligence)
    pub sha256_hash: Option<String>,
    /// Perceptual image hash (for media near-duplicate detection)
    pub perceptual_hash: Option<u64>,
    /// Heuristic space reclamation classification
    pub clean_tier: CleanTier,
    /// Specific category name (e.g., "Package Cache (npm)", "Build Tree (target)")
    pub clean_category: Option<String>,
    /// Security audit findings
    pub security_findings: Vec<SecurityFinding>,
    /// Authenticode signature status
    pub authenticode_status: Option<String>,
    /// Embedded PE version information (ProductName, FileVersion, OriginalFilename)
    pub pe_version_info: Option<PeVersionMetadata>,
    /// Whether the file is located within a designated protected Reference Folder
    pub is_in_reference_folder: bool,
    /// Whether the file is currently locked by active running processes
    pub locking_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeVersionMetadata {
    pub product_name: String,
    pub company_name: String,
    pub file_version: String,
    pub product_version: String,
    pub original_filename: String,
    pub is_masquerading: bool,
}

/// Group of duplicate files sharing identical content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub file_size: u64,
    pub blake3_hash: String,
    pub reclaimable_bytes: u64,
    /// Files in this duplicate group
    pub files: Vec<ScannedFile>,
}

/// Aggregate statistics of a completed scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files_scanned: usize,
    pub total_directories_scanned: usize,
    pub total_logical_bytes: u64,
    pub total_physical_bytes: u64,
    pub safe_reclaimable_bytes: u64,
    pub review_reclaimable_bytes: u64,
    pub total_duplicates_count: usize,
    pub duplicate_reclaimable_bytes: u64,
    pub cloud_placeholders_count: usize,
    pub broken_symlinks_count: usize,
    pub security_findings_count: usize,
    pub critical_vulnerabilities_count: usize,
    pub scan_duration_ms: u64,
}

/// Configuration options for the scanning engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_paths: Vec<PathBuf>,
    pub reference_folders: Vec<PathBuf>,
    pub minimal_file_size: u64,
    pub inspect_ads: bool,
    pub compute_full_hashes: bool,
    pub audit_security: bool,
    pub audit_amsi: bool,
    pub check_online_hashes: bool,
    pub max_threads: usize,
    pub quarantine_directory: Option<PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_paths: vec![PathBuf::from(".")],
            reference_folders: Vec::new(),
            minimal_file_size: 8192, // 8 KB CLI default (per docx)
            inspect_ads: false,
            compute_full_hashes: true,
            audit_security: true,
            audit_amsi: true,
            check_online_hashes: false,
            max_threads: 0, // 0 = automatic rayon pool
            quarantine_directory: None,
        }
    }
}
