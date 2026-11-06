//! Security Audit Command Handler
//!
//! Orchestrates Win32 DACL/ACL audits, Authenticode verification,
//! AMSI dynamic script checks, and static pattern matching.

use scanner_core::models::{ScannedFile, SecuritySeverity};
use scanner_core::security::audit_files_security;

pub fn execute_security_audit(files: &mut [ScannedFile], enable_amsi: bool) {
    println!("\n=== WinSentry: Multi-Layered Endpoint Security Audit ===");
    println!("Auditing {} files across 4 orthogonal security layers...", files.len());
    println!("  Layer 1: Win32 DACL / ACL Local Privilege Escalation & SeriousSAM");
    println!("  Layer 2: Binary Authenticity, Extension Masquerading & Authenticode");
    println!("  Layer 3: Dynamic Script Inspection via Windows AMSI (amsi.dll)");
    println!("  Layer 4: Static Pattern Matching (Ransomware commands & Secrets)");

    audit_files_security(files, enable_amsi);

    let mut total_findings = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    for f in files.iter() {
        for finding in &f.security_findings {
            total_findings += 1;
            match finding.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                _ => {}
            }
        }
    }

    println!("\n=== Security Audit Results ===");
    println!("Total Findings:     {}", total_findings);
    println!("Critical Severity:  {}", critical_count);
    println!("High Severity:      {}", high_count);

    if total_findings == 0 {
        println!("\n[OK] No security vulnerabilities or threat indicators detected.");
        return;
    }

    println!("\nDetailed Security Findings:");
    for f in files.iter().filter(|f| !f.security_findings.is_empty()) {
        println!("\nFile: {}", f.display_path);
        for finding in &f.security_findings {
            let sev_tag = match finding.severity {
                SecuritySeverity::Critical => "[CRITICAL]",
                SecuritySeverity::High => "[HIGH]",
                SecuritySeverity::Medium => "[MEDIUM]",
                SecuritySeverity::Low => "[LOW]",
                SecuritySeverity::Info => "[INFO]",
            };
            println!("  {} [{}]: {}", sev_tag, finding.category, finding.title);
            println!("     Detail: {}", finding.description);
            println!("     Advice: {}", finding.remediation_advice);
        }
    }
}
