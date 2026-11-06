//! WinSentry CLI - High-Velocity Storage Reclamation and Security Engine

mod commands;

use clap::{Parser, Subcommand};
use commands::clean::{execute_cleanup, CleanOptions};
use commands::dedup::execute_dedup;
use commands::scan::{execute_full_scan, ScanOutputOptions};
use commands::security::execute_security_audit;
use commands::server::start_dashboard_server;
use commands::vss::execute_vss_advisory;
use scanner_core::models::ScanConfig;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "winsentry")]
#[command(author = "Arhan Ghosarwade <arhanghosarwade05@gmail.com>")]
#[command(version = scanner_core::VERSION)]
#[command(
    about = "WinSentry - High-Velocity Windows Storage Reclamation & Security Auditing Engine",
    long_about = "A production-grade, memory-safe systems utility bridging high-throughput Windows storage reclamation with deep endpoint security and vulnerability auditing."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Full dual-engine storage telemetry and security vulnerability scan
    Scan {
        /// Target directories or volumes to scan (defaults to current directory)
        #[arg(short, long, default_values = ["."])]
        path: Vec<PathBuf>,

        /// Minimum file size floor for deduplication and deep inspection (in bytes)
        #[arg(short, long, default_value_t = 8192)]
        minimal_size: u64,

        /// Protected reference folders (files within are never marked for deletion)
        #[arg(short, long)]
        reference: Vec<PathBuf>,

        /// Inspect Alternate Data Streams (ADS)
        #[arg(long)]
        ads: bool,

        /// Skip AMSI dynamic script scanning
        #[arg(long)]
        skip_amsi: bool,

        /// Path to export standalone interactive D3.js Squarified Treemap HTML report
        #[arg(long)]
        report_html: Option<PathBuf>,

        /// Path to export machine-readable JSON telemetry report
        #[arg(long)]
        report_json: Option<PathBuf>,

        /// Path to export analytics CSV report
        #[arg(long)]
        report_csv: Option<PathBuf>,
    },

    /// Dedicated two-stage cryptographic deduplication (prehash + Blake3)
    Dedup {
        /// Target directory or volume to scan for duplicate files
        #[arg(short, long, default_values = ["."])]
        path: Vec<PathBuf>,

        /// Minimum file size floor in bytes (default: 8192)
        #[arg(short, long, default_value_t = 8192)]
        minimal_size: u64,

        /// Protected reference folders
        #[arg(short, long)]
        reference: Vec<PathBuf>,

        /// Replace redundant duplicate files with NTFS Hardlinks to reclaim clusters
        #[arg(long)]
        hardlink: bool,
    },

    /// Dedicated 4-layer endpoint security and vulnerability audit
    Security {
        /// Target directory or volume to audit
        #[arg(short, long, default_values = ["."])]
        path: Vec<PathBuf>,

        /// Disable AMSI script scanning
        #[arg(long)]
        skip_amsi: bool,
    },

    /// Safe guided space reclamation with Recycle Bin and Restart Manager checks
    Clean {
        /// Target directory or volume to scan and clean
        #[arg(short, long, default_values = ["."])]
        path: Vec<PathBuf>,

        /// Purge only [SAFE] tier targets (package caches, temporary files, crash dumps)
        #[arg(long, default_value_t = true)]
        safe_only: bool,

        /// Preview actions without deleting or modifying any files
        #[arg(long)]
        dry_run: bool,

        /// Permanently delete files bypassing the Recycle Bin
        #[arg(long)]
        permanent: bool,

        /// Relocate cleaned files to a designated quarantine staging directory
        #[arg(long)]
        quarantine: Option<PathBuf>,
    },

    /// Volume Shadow Copy (VSS) inspection and system restore point advisory
    Vss,

    /// Launch interactive local web control center and live visual treemap
    Serve {
        /// Local port to bind the dashboard server (default: 7878)
        #[arg(short, long, default_value_t = 7878)]
        port: u16,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            minimal_size,
            reference,
            ads,
            skip_amsi,
            report_html,
            report_json,
            report_csv,
        } => {
            let mut config = ScanConfig::default();
            config.target_paths = path.clone();
            config.reference_folders = reference;
            config.minimal_file_size = minimal_size;
            config.inspect_ads = ads;
            config.audit_amsi = !skip_amsi;

            let output_opts = ScanOutputOptions {
                html_report: report_html,
                json_report: report_json,
                csv_report: report_csv,
            };

            execute_full_scan(&path, &config, &output_opts);
        }

        Commands::Dedup {
            path,
            minimal_size,
            reference,
            hardlink,
        } => {
            let mut config = ScanConfig::default();
            config.target_paths = path.clone();
            config.minimal_file_size = minimal_size;
            config.reference_folders = reference.clone();
            config.audit_security = false;

            let output_opts = ScanOutputOptions {
                html_report: None,
                json_report: None,
                csv_report: None,
            };

            let (mut files, _) = execute_full_scan(&path, &config, &output_opts);
            execute_dedup(&mut files, minimal_size, &reference, hardlink);
        }

        Commands::Security { path, skip_amsi } => {
            let mut config = ScanConfig::default();
            config.target_paths = path.clone();
            config.audit_security = true;
            config.audit_amsi = !skip_amsi;

            let output_opts = ScanOutputOptions {
                html_report: None,
                json_report: None,
                csv_report: None,
            };

            let (mut files, _) = execute_full_scan(&path, &config, &output_opts);
            execute_security_audit(&mut files, !skip_amsi);
        }

        Commands::Clean {
            path,
            safe_only,
            dry_run,
            permanent,
            quarantine,
        } => {
            let mut config = ScanConfig::default();
            config.target_paths = path.clone();

            let output_opts = ScanOutputOptions {
                html_report: None,
                json_report: None,
                csv_report: None,
            };

            let (files, _) = execute_full_scan(&path, &config, &output_opts);

            let clean_opts = CleanOptions {
                safe_only,
                dry_run,
                _use_recycle_bin: !permanent && quarantine.is_none(),
                permanent,
                quarantine_dir: quarantine,
            };

            execute_cleanup(&files, &clean_opts);
        }

        Commands::Vss => {
            execute_vss_advisory();
        }

        Commands::Serve { port } => {
            if let Err(e) = start_dashboard_server(port) {
                eprintln!("[ERROR] Dashboard server error: {}", e);
            }
        }
    }
}
