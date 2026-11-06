//! Scan Command Handler
//!
//! Orchestrates the full four-stage pipeline:
//! 1. High-velocity Win32 kernel directory traversal
//! 2. NTFS cluster accounting and heuristic tier classification
//! 3. Two-stage cryptographic deduplication
//! 4. Endpoint security and vulnerability auditing
//! 5. Standalone D3 HTML treemap and JSON/CSV reporting

use scanner_core::classifier::classify_file;
use scanner_core::dedup::find_duplicates;
use scanner_core::models::{CleanTier, ScanConfig, ScannedFile, ScanSummary};
use scanner_core::reporting::{export_csv_report, export_html_report, export_json_report};
use scanner_core::security::audit_files_security;
use scanner_core::win32::traversal::traverse_tree_parallel;
use std::path::PathBuf;
use std::time::Instant;

pub struct ScanOutputOptions {
    pub html_report: Option<PathBuf>,
    pub json_report: Option<PathBuf>,
    pub csv_report: Option<PathBuf>,
}

pub fn execute_full_scan(
    targets: &[PathBuf],
    config: &ScanConfig,
    output_opts: &ScanOutputOptions,
) -> (Vec<ScannedFile>, ScanSummary) {
    let start_time = Instant::now();

    println!("============================================================");
    println!(" WinSentry: High-Velocity Storage & Security Auditing Engine");
    println!("============================================================");
    println!("Target Path(s): {:?}", targets);
    println!("Min Size Floor: {} bytes", config.minimal_file_size);
    println!("Security Audit: {}", if config.audit_security { "Enabled" } else { "Disabled" });
    println!("AMSI Dynamic:   {}", if config.audit_amsi { "Enabled" } else { "Disabled" });
    println!("------------------------------------------------------------");

    // 1. Filesystem Traversal
    print!("[Stage 1/4] Traversing filesystem via Win32 FindFirstFileExW... ");
    let mut all_files = Vec::new();

    for t in targets {
        let files = traverse_tree_parallel(t, None::<fn(usize)>);
        all_files.extend(files);
    }
    println!("Done. Discovered {} entries.", all_files.len());

    // 2. Storage Accounting & Heuristic Tier Classification
    print!("[Stage 2/4] Computing NTFS clusters & heuristic space tiers... ");
    for f in all_files.iter_mut() {
        classify_file(f);
    }
    println!("Done.");

    // 3. Two-Stage Deduplication
    print!("[Stage 3/4] Running two-stage cryptographic deduplication... ");
    let duplicate_groups = find_duplicates(
        &mut all_files,
        config.minimal_file_size,
        &config.reference_folders,
    );
    println!("Done. Found {} duplicate groups.", duplicate_groups.len());

    // 4. Security & Vulnerability Auditing
    if config.audit_security {
        print!("[Stage 4/4] Executing 4-layer endpoint vulnerability audit... ");
        audit_files_security(&mut all_files, config.audit_amsi);
        println!("Done.");
    } else {
        println!("[Stage 4/4] Security audit skipped per configuration.");
    }

    let elapsed = start_time.elapsed();

    // Compute Summary Statistics
    let mut summary = ScanSummary::default();
    summary.total_files_scanned = all_files.iter().filter(|f| !f.is_directory).count();
    summary.total_directories_scanned = all_files.iter().filter(|f| f.is_directory).count();
    summary.scan_duration_ms = elapsed.as_millis() as u64;

    for f in &all_files {
        summary.total_logical_bytes += f.logical_size;
        summary.total_physical_bytes += f.physical_size;
        if f.is_cloud_placeholder {
            summary.cloud_placeholders_count += 1;
        }
        if f.is_broken_link {
            summary.broken_symlinks_count += 1;
        }
        match f.clean_tier {
            CleanTier::Safe => summary.safe_reclaimable_bytes += f.physical_size,
            CleanTier::Review => summary.review_reclaimable_bytes += f.physical_size,
            _ => {}
        }
        summary.security_findings_count += f.security_findings.len();
        summary.critical_vulnerabilities_count += f
            .security_findings
            .iter()
            .filter(|s| s.severity == scanner_core::models::SecuritySeverity::Critical)
            .count();
    }

    summary.total_duplicates_count = duplicate_groups.iter().map(|g| g.files.len()).sum();
    summary.duplicate_reclaimable_bytes = duplicate_groups.iter().map(|g| g.reclaimable_bytes).sum();

    // Print Rich Terminal Summary
    println!("\n=================== SCAN TELEMETRY SUMMARY ===================");
    println!("Traversal Time:            {:.2} seconds", elapsed.as_secs_f64());
    println!("Files Scanned:             {}", summary.total_files_scanned);
    println!("Directories Scanned:       {}", summary.total_directories_scanned);
    println!(
        "Total Logical Size:        {:.2} GB",
        (summary.total_logical_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    );
    println!(
        "Total Physical Size (NTFS):{:.2} GB",
        (summary.total_physical_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    );
    println!("------------------------------------------------------------");
    println!(
        "[SAFE] Deterministic Purge: {:.2} MB (Zero data-loss caches/dumps)",
        (summary.safe_reclaimable_bytes as f64) / (1024.0 * 1024.0)
    );
    println!(
        "[REVIEW] Contextual Audit:  {:.2} MB (Build trees / archives / cold storage)",
        (summary.review_reclaimable_bytes as f64) / (1024.0 * 1024.0)
    );
    println!(
        "Duplicate Reclaimable:     {:.2} MB (Across {} groups)",
        (summary.duplicate_reclaimable_bytes as f64) / (1024.0 * 1024.0),
        duplicate_groups.len()
    );
    println!("------------------------------------------------------------");
    println!("Security Findings:         {}", summary.security_findings_count);
    println!("Critical Vulnerabilities:  {}", summary.critical_vulnerabilities_count);
    println!("Cloud Recall Placeholders: {} (protected from download)", summary.cloud_placeholders_count);
    println!("Broken Symlinks/Junctions: {}", summary.broken_symlinks_count);
    println!("============================================================\n");

    // Generate Reports
    if let Some(ref html_path) = output_opts.html_report {
        match export_html_report(html_path, &summary, &all_files, &duplicate_groups) {
            Ok(_) => println!("[REPORT] Saved Standalone D3 Treemap HTML -> {}", html_path.display()),
            Err(e) => eprintln!("[ERROR] Failed to export HTML report: {}", e),
        }
    }

    if let Some(ref json_path) = output_opts.json_report {
        match export_json_report(json_path, &summary, &all_files, &duplicate_groups) {
            Ok(_) => println!("[REPORT] Saved Machine-Readable JSON -> {}", json_path.display()),
            Err(e) => eprintln!("[ERROR] Failed to export JSON report: {}", e),
        }
    }

    if let Some(ref csv_path) = output_opts.csv_report {
        match export_csv_report(csv_path, &all_files) {
            Ok(_) => println!("[REPORT] Saved Analytics CSV Spreadsheet -> {}", csv_path.display()),
            Err(e) => eprintln!("[ERROR] Failed to export CSV report: {}", e),
        }
    }

    (all_files, summary)
}
