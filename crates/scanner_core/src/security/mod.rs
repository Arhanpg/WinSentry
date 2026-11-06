//! Multi-Layered Endpoint Security and Vulnerability Auditing Engine
//!
//! Orchestrates orthogonal security assessments across all discovered files:
//! 1. Win32 DACL / ACL Local Privilege Escalation & SeriousSAM
//! 2. Binary authenticity, magic-byte masquerading, and Authenticode
//! 3. Static signature / secret scanning (ransomware, API tokens, bypasses)
//! 4. Dynamic script scanning via AMSI (with Defender offline detection)
//! 5. Hash intelligence (NSRL Known-Good clearance & MalwareBazaar)

pub mod acl;
pub mod amsi;
pub mod authenticity;
pub mod signatures;

use crate::models::ScannedFile;
use acl::audit_file_acl;
use amsi::{audit_file_with_amsi, AmsiScanner};
use authenticity::{audit_magic_bytes_and_masquerading, verify_authenticode_signature};
use rayon::prelude::*;
use signatures::{audit_hash_intelligence, audit_static_patterns, get_known_good_hashes};
use std::sync::atomic::{AtomicBool, Ordering};

/// Audits a collection of scanned files across all 4 security layers
pub fn audit_files_security(files: &mut [ScannedFile], enable_amsi: bool) {
    let amsi_scanner = if enable_amsi { AmsiScanner::new() } else { None };
    let defender_alerted = AtomicBool::new(false);
    let known_good = get_known_good_hashes();

    files.par_iter_mut().for_each(|file| {
        // 1. DACL / LPE and Sensitive Registry Audit
        audit_file_acl(file);

        // 2. Magic bytes and extension masquerading
        audit_magic_bytes_and_masquerading(file);

        // 3. Authenticode digital signature check on PE binaries
        let is_pe = file.extension == "exe"
            || file.extension == "dll"
            || file.extension == "sys"
            || file.extension == "msi";
        if is_pe && !file.is_directory {
            let (is_valid, msg) = verify_authenticode_signature(&file.path);
            file.authenticode_status = Some(msg);
            if !is_valid {
                // If in AppData or Temp, flag as high alert
                let p_lower = file.display_path.to_ascii_lowercase();
                if p_lower.contains("appdata") || p_lower.contains("temp") {
                    file.security_findings.push(crate::models::SecurityFinding {
                        severity: crate::models::SecuritySeverity::High,
                        category: "Unsigned Binary in User Profile".to_string(),
                        title: "Unsigned or Untrusted Binary in AppData/Temp".to_string(),
                        description: format!(
                            "The executable binary at '{}' lacks a verified Authenticode signature while residing in a high-risk user location.",
                            file.display_path
                        ),
                        remediation_advice: "Verify application publisher before executing.".to_string(),
                    });
                }
            }
        }

        // 4. Static pattern matching (secrets, ransomware staging, etc.)
        audit_static_patterns(file);

        // 5. Hash intelligence (Known-good vs known-malware)
        audit_hash_intelligence(file, &known_good);

        // 6. Dynamic script inspection via AMSI
        if enable_amsi && amsi_scanner.is_some() {
            let mut alerted = defender_alerted.load(Ordering::Relaxed);
            audit_file_with_amsi(file, amsi_scanner.as_ref(), &mut alerted);
            if alerted {
                defender_alerted.store(true, Ordering::Relaxed);
            }
        }
    });
}
