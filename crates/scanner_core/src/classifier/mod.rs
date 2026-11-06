//! Heuristic Space Reclamation Classifier
//!
//! Classifies discovered filesystem targets into deterministic action tiers:
//! - [SAFE]: Package manager caches, shader caches, crash dumps, empty files/dirs
//! - [REVIEW]: Extracted archives adjacent to sibling folders, build trees, dormant cold storage
//! - [ADVISORY]: Volume Shadow Copies (VSS)

use crate::models::{CleanTier, ScannedFile};
use std::path::Path;
use std::process::Command;

/// Checks if a file path belongs to a package manager cache
pub fn is_package_cache(path_lower: &str) -> Option<&'static str> {
    if path_lower.contains(r"npm\_cacache") || path_lower.contains("npm/_cacache") {
        Some("Package Cache (npm)")
    } else if path_lower.contains("pnpm-cache") || path_lower.contains(r"pnpm\store") {
        Some("Package Cache (pnpm)")
    } else if path_lower.contains(r"pip\cache") || path_lower.contains("pip/cache") {
        Some("Package Cache (pip)")
    } else if path_lower.contains(r"uv\cache") || path_lower.contains("uv/cache") {
        Some("Package Cache (uv)")
    } else if path_lower.contains(r"conda\pkgs") || path_lower.contains("conda/pkgs") {
        Some("Package Cache (conda)")
    } else if path_lower.contains(r".cargo\registry\cache") || path_lower.contains(".cargo/registry/cache") {
        Some("Package Cache (cargo)")
    } else if path_lower.contains(r".nuget\packages") || path_lower.contains(".nuget/packages") {
        Some("Package Cache (nuget)")
    } else {
        None
    }
}

/// Checks if a file path belongs to graphics or OS staging caches
pub fn is_graphics_or_os_staging(path_lower: &str, ext: &str) -> Option<&'static str> {
    if path_lower.contains("dxcache") {
        Some("DirectX Shader Cache (DXCache)")
    } else if path_lower.contains("shadercache") {
        Some("GPU Shader Cache")
    } else if path_lower.contains(r"appdata\local\temp") || path_lower.contains("appdata/local/temp") {
        Some("User Temp Directory")
    } else if path_lower.contains(r"windows\temp") || path_lower.contains("windows/temp") {
        Some("Windows Temp Directory")
    } else if ext == "dmp" || path_lower.contains("crashdumps") {
        Some("Crash Dump File (.dmp)")
    } else if ext == "tmp" {
        Some("Temporary File (.tmp)")
    } else {
        None
    }
}

/// Checks if a file path belongs to a rebuildable build tree
pub fn is_build_tree(path_lower: &str) -> Option<&'static str> {
    if path_lower.contains(r"\target\debug\")
        || path_lower.contains(r"\target\release\")
        || path_lower.ends_with(r"\target")
        || path_lower.contains("/target/debug/")
        || path_lower.contains("/target/release/")
    {
        Some("Rust Build Tree (target/)")
    } else if path_lower.contains(r"\node_modules\") || path_lower.ends_with(r"\node_modules") || path_lower.contains("/node_modules/") {
        Some("Node.js Dependencies (node_modules/)")
    } else if path_lower.contains(r"\.venv\") || path_lower.contains(r"\venv\") || path_lower.contains("/.venv/") || path_lower.contains("/venv/") {
        Some("Python Virtual Environment (.venv/)")
    } else if path_lower.contains(r"\__pycache__\") || path_lower.contains("/__pycache__/") || path_lower.ends_with("__pycache__") {
        Some("Python Bytecode Cache (__pycache__/)")
    } else if path_lower.contains(r"\bin\debug\") || path_lower.contains(r"\bin\release\") || path_lower.contains(r"\obj\debug\") {
        Some(".NET Build Output (bin/obj)")
    } else {
        None
    }
}

/// Checks whether an archive sits adjacent to an already-extracted sibling folder sharing the same stem
pub fn is_redundant_extracted_archive(file: &ScannedFile) -> bool {
    let ext = &file.extension;
    if ext != "zip" && ext != "tar" && ext != "gz" && ext != "7z" && ext != "rar" {
        return false;
    }

    if let Some(parent) = file.path.parent() {
        let stem = match Path::new(&file.file_name).file_stem() {
            Some(s) => s.to_string_lossy().to_string(),
            None => return false,
        };

        let mut sibling_dir = parent.to_path_buf();
        sibling_dir.push(&stem);

        if sibling_dir.is_dir() {
            return true;
        }
    }
    false
}

/// Classifies a scanned file into its appropriate CleanTier
pub fn classify_file(file: &mut ScannedFile) {
    let path_lower = file.display_path.to_ascii_lowercase();
    let ext = &file.extension;

    // Check [SAFE] tier first
    // 1. Structural clutter: 0-byte empty files, broken links
    if file.is_broken_link {
        file.clean_tier = CleanTier::Safe;
        file.clean_category = Some("Broken Symlink / Junction".to_string());
        return;
    }

    if !file.is_directory && file.logical_size == 0 && !file.is_cloud_placeholder {
        file.clean_tier = CleanTier::Safe;
        file.clean_category = Some("Empty Zero-Byte File".to_string());
        return;
    }

    // 2. Package manager caches
    if let Some(cat) = is_package_cache(&path_lower) {
        file.clean_tier = CleanTier::Safe;
        file.clean_category = Some(cat.to_string());
        return;
    }

    // 3. Graphics & OS staging
    if let Some(cat) = is_graphics_or_os_staging(&path_lower, ext) {
        file.clean_tier = CleanTier::Safe;
        file.clean_category = Some(cat.to_string());
        return;
    }

    // Check [REVIEW] tier
    // 1. Extracted archives adjacent to folder
    if is_redundant_extracted_archive(file) {
        file.clean_tier = CleanTier::Review;
        file.clean_category = Some("Extracted Archive with Adjacent Sibling Folder".to_string());
        return;
    }

    // 2. Rebuildable build trees
    if let Some(cat) = is_build_tree(&path_lower) {
        file.clean_tier = CleanTier::Review;
        file.clean_category = Some(cat.to_string());
        return;
    }

    // 3. Dormant cold storage: files > 100 MB unmodified for > 180 days
    const COLD_STORAGE_THRESHOLD_BYTES: u64 = 100 * 1024 * 1024;
    const COLD_STORAGE_THRESHOLD_DAYS: u32 = 180;

    if file.logical_size >= COLD_STORAGE_THRESHOLD_BYTES && file.age_days >= COLD_STORAGE_THRESHOLD_DAYS {
        file.clean_tier = CleanTier::Review;
        file.clean_category = Some(format!(
            "Dormant Cold Storage (>{} MB, unmodified {} days)",
            file.logical_size / (1024 * 1024),
            file.age_days
        ));
        return;
    }

    file.clean_tier = CleanTier::Active;
}

/// Volume Shadow Copy advisory information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShadowCopyInfo {
    pub volume_name: String,
    pub used_space: String,
    pub allocated_space: String,
    pub max_space: String,
    pub shadow_count: usize,
    pub advisory_note: String,
}

/// Queries VSS shadow storage using vssadmin (read-only advisory)
pub fn query_vss_advisory() -> Result<ShadowCopyInfo, String> {
    let output = Command::new("vssadmin")
        .args(["list", "shadowstorage"])
        .output()
        .map_err(|e| format!("Failed to execute vssadmin: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut used_space = "Unknown".to_string();
    let mut allocated_space = "Unknown".to_string();
    let mut max_space = "Unknown".to_string();

    for line in stdout.lines() {
        let line_trim = line.trim();
        if line_trim.starts_with("Used Shadow Copy Storage space:") {
            used_space = line_trim.replace("Used Shadow Copy Storage space:", "").trim().to_string();
        } else if line_trim.starts_with("Allocated Shadow Copy Storage space:") {
            allocated_space = line_trim.replace("Allocated Shadow Copy Storage space:", "").trim().to_string();
        } else if line_trim.starts_with("Maximum Shadow Copy Storage space:") {
            max_space = line_trim.replace("Maximum Shadow Copy Storage space:", "").trim().to_string();
        }
    }

    Ok(ShadowCopyInfo {
        volume_name: "C:\\".to_string(),
        used_space,
        allocated_space,
        max_space,
        shadow_count: 0,
        advisory_note: "[ADVISORY] Deleting all shadow copies with 'vssadmin delete shadows /for=C: /all' destroys System Restore points. Only '/oldest' or specific '/Shadow={ID}' should ever be purged if space is critically exhausted.".to_string(),
    })
}
