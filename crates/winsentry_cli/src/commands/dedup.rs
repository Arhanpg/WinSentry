//! Deduplication Command Handler
//!
//! Orchestrates size grouping, start/end edge prehashing, full Blake3 hashing,
//! and optional NTFS hardlink replacement for reclaimed storage.

use scanner_core::dedup::find_duplicates;
use scanner_core::models::ScannedFile;
use scanner_core::remediation::hardlink_duplicate;
use std::path::PathBuf;

pub fn execute_dedup(
    files: &mut [ScannedFile],
    minimal_size: u64,
    reference_folders: &[PathBuf],
    replace_with_hardlinks: bool,
) {
    println!("\n=== WinSentry: Two-Stage Cryptographic Deduplication ===");
    println!("Minimum size floor:  {} bytes", minimal_size);
    if !reference_folders.is_empty() {
        println!("Protected Reference Folders: {}", reference_folders.len());
        for rf in reference_folders {
            println!("  * {}", rf.display());
        }
    }

    let duplicate_groups = find_duplicates(files, minimal_size, reference_folders);

    if duplicate_groups.is_empty() {
        println!("No duplicate files found meeting the size floor criteria.");
        return;
    }

    let total_reclaimable: u64 = duplicate_groups.iter().map(|g| g.reclaimable_bytes).sum();
    let total_dup_files: usize = duplicate_groups.iter().map(|g| g.files.len()).sum();

    println!(
        "\nDiscovered {} duplicate groups containing {} files ({:.2} MB reclaimable space):",
        duplicate_groups.len(),
        total_dup_files,
        (total_reclaimable as f64) / (1024.0 * 1024.0)
    );

    for (i, group) in duplicate_groups.iter().take(15).enumerate() {
        println!(
            "\n[Group #{}] Size: {:.2} KB | Blake3: {}... | Reclaimable: {:.2} KB",
            i + 1,
            (group.file_size as f64) / 1024.0,
            &group.blake3_hash[..12],
            (group.reclaimable_bytes as f64) / 1024.0
        );

        for (f_idx, file) in group.files.iter().enumerate() {
            let ref_tag = if file.is_in_reference_folder { " [PROTECTED MASTER]" } else { "" };
            println!("   {}. {}{}", f_idx + 1, file.display_path, ref_tag);
        }

        // Handle Hardlink replacement if requested
        if replace_with_hardlinks && group.files.len() > 1 {
            let master = &group.files[0];
            for dup in &group.files[1..] {
                if !dup.is_in_reference_folder {
                    print!("   Linking {} -> master ... ", dup.file_name);
                    match hardlink_duplicate(&dup.path, &master.path) {
                        Ok(_) => println!("[OK] Reclaimed 100% physical clusters!"),
                        Err(e) => println!("[SKIP] {}", e),
                    }
                }
            }
        }
    }

    if duplicate_groups.len() > 15 {
        println!("\n... and {} more duplicate groups.", duplicate_groups.len() - 15);
    }
}
