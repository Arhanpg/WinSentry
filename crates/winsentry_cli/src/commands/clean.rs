//! Safe Cleanup Command Handler
//!
//! Enforces Reference Folder immutability, checks for active process locks
//! via Windows Restart Manager, and routes deleted files safely to $RECYCLE.BIN
//! with full Explorer Undo metadata.

use scanner_core::models::{CleanTier, ScannedFile};
use scanner_core::remediation::{check_process_locks, fast_delete_file_or_dir, move_to_recycle_bin, quarantine_file};
use std::path::{Path, PathBuf};

pub struct CleanOptions {
    pub safe_only: bool,
    pub dry_run: bool,
    pub _use_recycle_bin: bool,
    pub permanent: bool,
    pub quarantine_dir: Option<PathBuf>,
}

pub fn execute_cleanup(
    files: &[ScannedFile],
    options: &CleanOptions,
) {
    println!("\n=== WinSentry Safe Cleanup & Space Reclamation ===");

    // 1. Identify candidate files
    let candidates: Vec<&ScannedFile> = files
        .iter()
        .filter(|f| {
            if f.is_in_reference_folder {
                return false; // Reference Folders are strictly immutable
            }
            if options.safe_only {
                f.clean_tier == CleanTier::Safe
            } else {
                f.clean_tier == CleanTier::Safe || f.clean_tier == CleanTier::Review
            }
        })
        .collect();

    if candidates.is_empty() {
        println!("No files matched the specified cleanup criteria.");
        return;
    }

    let total_reclaimable: u64 = candidates.iter().map(|f| f.physical_size).sum();
    println!(
        "Identified {} candidate files eligible for cleanup ({:.2} MB on disk).",
        candidates.len(),
        (total_reclaimable as f64) / (1024.0 * 1024.0)
    );

    // 2. Pre-flight check: Windows Restart Manager process locks
    let target_paths: Vec<&Path> = candidates.iter().map(|f| f.path.as_path()).collect();
    println!("Checking for active process locks via Windows Restart Manager...");
    let locks = check_process_locks(&target_paths);

    if !locks.is_empty() {
        println!("\n[WARNING] Active Process Locks Detected on {} files:", locks.len());
        for (locked_path, procs) in &locks {
            println!("  File: {}", locked_path.display());
            for p in procs {
                println!("    -> PID {}: '{}' (service: '{}')", p.process_id, p.app_name, p.service_name);
            }
        }
        println!("\nPlease close the locking processes or run with administrator privileges to avoid sharing violations.");
    }

    if options.dry_run {
        println!("\n--- [DRY-RUN] Preview of Clean Actions (No files modified) ---");
        for f in candidates.iter().take(20) {
            println!(
                "  {} {} ({:.1} KB) -> {}",
                f.clean_tier.label(),
                f.display_path,
                (f.physical_size as f64) / 1024.0,
                f.clean_category.as_deref().unwrap_or("Cache/Staging")
            );
        }
        if candidates.len() > 20 {
            println!("  ... and {} more files.", candidates.len() - 20);
        }
        println!("\nTotal potential physical space reclaimed: {:.2} MB", (total_reclaimable as f64) / (1024.0 * 1024.0));
        return;
    }

    // 3. Execution Phase
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut reclaimed_bytes: u64 = 0;

    for f in candidates {
        let res = if let Some(ref q_dir) = options.quarantine_dir {
            quarantine_file(&f.path, q_dir, "WinSentry Clean Action", f.blake3_hash.as_deref())
                .map(|_| ())
        } else if options.permanent {
            fast_delete_file_or_dir(&f.path)
        } else {
            // Default: Safe disposal via Recycle Bin with Undo support
            move_to_recycle_bin(&f.path)
        };

        match res {
            Ok(_) => {
                success_count += 1;
                reclaimed_bytes += f.physical_size;
            }
            Err(e) => {
                fail_count += 1;
                eprintln!("[FAIL] Could not remove {}: {}", f.display_path, e);
            }
        }
    }

    println!("\n=== Cleanup Operation Finished ===");
    println!("Successfully processed: {} files", success_count);
    if fail_count > 0 {
        println!("Failed / Skipped:        {} files", fail_count);
    }
    println!(
        "Physical space reclaimed: {:.2} MB",
        (reclaimed_bytes as f64) / (1024.0 * 1024.0)
    );
    if options.quarantine_dir.is_none() && !options.permanent {
        println!("Note: Deleted files were sent to $RECYCLE.BIN. You can press Ctrl+Z in Windows Explorer to undo if needed.");
    }
}
