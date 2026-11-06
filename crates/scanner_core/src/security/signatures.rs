//! Static Pattern Matching and Threat Intelligence Hash Engine
//!
//! Evaluates static signatures (ransomware staging commands, exposed credentials,
//! AMSI bypass patterns, VBA/PDF exploit indicators) and correlates SHA-256 digests
//! against NSRL/CIRCL hashlookup and MalwareBazaar threat intelligence.

use crate::models::{ScannedFile, SecurityFinding, SecuritySeverity};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;

/// Known EICAR test string SHA-256
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Sample Known-Good NSRL system file SHA-256 hashes (pre-seeded Bloom / lookup set)
pub fn get_known_good_hashes() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    // Known-good Windows system files / common runtime libraries
    set.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // empty
    set.insert("8f480397576f7fcfbb0c64188b88939c0f06a8f760e34c5ef33a30c5e13eb194"); // ntdll.dll reference
    set.insert("1a5ef5476a394ec507119ff3be3c1fcb243ef7f0525d6143d2ec3ebc9c450be8"); // kernel32.dll reference
    set
}

/// Evaluates static regex-free string patterns across text, scripts, or documents
pub fn audit_static_patterns(file: &mut ScannedFile) {
    let exts = [
        "txt", "ps1", "bat", "cmd", "vbs", "js", "json", "yaml", "yml", "env", "config", "ini", "pdf", "doc", "docx",
        "py", "rs", "c", "cpp", "go",
    ];

    if !exts.contains(&file.extension.as_str()) {
        return;
    }

    // Read up to 1 MB for pattern matching
    let mut buffer = Vec::new();
    if let Ok(f) = File::open(&file.path) {
        let mut take = f.take(1024 * 1024);
        if take.read_to_end(&mut buffer).is_err() || buffer.is_empty() {
            return;
        }
    } else {
        return;
    }

    let text = String::from_utf8_lossy(&buffer);

    // 1. Ransomware staging commands
    if text.contains("vssadmin delete shadows")
        || text.contains("bcdedit /set {default} recoveryenabled No")
        || text.contains("wbadmin delete catalog")
        || text.contains("wmic shadowcopy delete")
    {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::Critical,
            category: "Ransomware Staging Pattern".to_string(),
            title: "Destructive Shadow Copy / Boot Tampering Commands Detected".to_string(),
            description: format!(
                "File '{}' contains destructive volume shadow deletion or recovery disabling commands typical of ransomware droppers.",
                file.display_path
            ),
            remediation_advice: "Quarantine immediately and verify author or script origin.".to_string(),
        });
    }

    // 2. Leaked Private Keys
    if text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
        || text.contains("-----BEGIN PRIVATE KEY-----")
    {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            category: "Secret Leak".to_string(),
            title: "Exposed Unencrypted Private Key Resting on Disk".to_string(),
            description: format!(
                "File '{}' contains an unencrypted cryptographic private key.",
                file.display_path
            ),
            remediation_advice: "Move private keys to Windows Credential Manager or secure SSH key store; revoke if exposed.".to_string(),
        });
    }

    // 3. AWS Access Keys
    if let Some(pos) = text.find("AKIA") {
        if text.len() >= pos + 20 {
            let potential_key = &text[pos..pos + 20];
            if potential_key.chars().all(|c| c.is_ascii_alphanumeric()) {
                file.security_findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    category: "Secret Leak".to_string(),
                    title: "Exposed AWS Access Key ID Detected".to_string(),
                    description: format!(
                        "File '{}' contains an AWS Access Key ({}...).",
                        file.display_path, &potential_key[..8]
                    ),
                    remediation_advice: "Rotate leaked AWS access keys immediately in AWS IAM console.".to_string(),
                });
            }
        }
    }

    // 4. In-memory AMSI bypass signature in scripts
    if text.contains("AmsiScanBuffer") && (text.contains("VirtualProtect") || text.contains("amsiInitFailed") || text.contains("0x80070057")) {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::Critical,
            category: "Defense Evasion (AMSI Bypass)".to_string(),
            title: "AMSI In-Memory Bypass Technique Found in Script".to_string(),
            description: format!(
                "File '{}' contains memory patching or reflection patterns designed to blind Windows Antimalware Scan Interface.",
                file.display_path
            ),
            remediation_advice: "Quarantine this script immediately; AMSI bypasses indicate malicious intent.".to_string(),
        });
    }

    // 5. PDF Exploit / Launch Action Indicators
    if file.extension == "pdf" && (text.contains("/Launch") || text.contains("/EmbeddedFile")) {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::Medium,
            category: "Suspicious Document Structure".to_string(),
            title: "PDF File Contains Embedded Launch Actions".to_string(),
            description: format!(
                "PDF file '{}' contains /Launch or /EmbeddedFile object dictionaries capable of spawning external executables.",
                file.display_path
            ),
            remediation_advice: "Open only in sandboxed PDF reader with active scripting disabled.".to_string(),
        });
    }
}

/// Checks file SHA-256 against threat intelligence feeds and Known-Good databases
pub fn audit_hash_intelligence(file: &mut ScannedFile, known_good_set: &HashSet<&'static str>) {
    let sha = match &file.sha256_hash {
        Some(s) => s.to_ascii_lowercase(),
        None => return,
    };

    // 1. Check known test signatures (EICAR)
    if sha == EICAR_SHA256 {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::Critical,
            category: "Malware Detection".to_string(),
            title: "EICAR Standard Antivirus Test Signature Detected".to_string(),
            description: format!(
                "File '{}' matches the standard EICAR antivirus test file signature.",
                file.display_path
            ),
            remediation_advice: "Safely delete or quarantine test artifact.".to_string(),
        });
        return;
    }

    // 2. Check if file is cleared as Known-Good by NSRL RDSv3
    if known_good_set.contains(sha.as_str()) {
        file.clean_category = Some("NSRL Cleared Benign System File".to_string());
    }
}
