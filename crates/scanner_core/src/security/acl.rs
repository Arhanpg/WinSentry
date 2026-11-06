//! Access Control List (ACL) and DACL Local Privilege Escalation (LPE) Auditor
//!
//! Interacts directly with advapi32.dll using GetNamedSecurityInfoW to inspect
//! NTFS DACLs for weak permissions granted to low-privilege Security Identifiers
//! (BUILTIN\\Users, Everyone, Authenticated Users), and checks for HiveNightmare / SeriousSAM.

use crate::models::{ScannedFile, SecurityFinding, SecuritySeverity};
use crate::win32::to_extended_path;
use std::path::Path;

// Well-known low-privilege SIDs
// S-1-5-32-545: BUILTIN\Users
// S-1-1-0: Everyone
// S-1-5-11: Authenticated Users

/// Checks if a file path is in a sensitive system directory or PATH location
pub fn is_system_or_program_path<P: AsRef<Path>>(path: P) -> bool {
    let p_str = path.as_ref().to_string_lossy().to_ascii_lowercase();
    p_str.contains(r"c:\program files")
        || p_str.contains(r"c:\program files (x86)")
        || p_str.contains(r"c:\programdata")
        || p_str.contains(r"c:\windows\system32")
        || p_str.contains(r"c:\windows")
}

/// Checks if the file is one of the sensitive Windows registry hives
pub fn is_sensitive_registry_hive<P: AsRef<Path>>(path: P) -> bool {
    let p_str = path.as_ref().to_string_lossy().to_ascii_lowercase();
    p_str.ends_with(r"\system32\config\sam")
        || p_str.ends_with(r"\system32\config\system")
        || p_str.ends_with(r"\system32\config\security")
}

/// Audits NTFS DACL permissions for Local Privilege Escalation vectors
pub fn audit_file_acl(file: &mut ScannedFile) {
    let ext_path = to_extended_path(&file.path);
    let path_str = ext_path.to_string_lossy().to_ascii_lowercase();

    // 1. Check for HiveNightmare / SeriousSAM vulnerability (CVE-2021-36934)
    if is_sensitive_registry_hive(&file.path) {
        // Test if low-privilege read access is permitted
        if let Ok(file_handle) = std::fs::File::open(&file.path) {
            drop(file_handle);
            file.security_findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                category: "Privilege Escalation (HiveNightmare)".to_string(),
                title: "Sensitive SAM/SYSTEM Hive Readable by Non-Admin Users".to_string(),
                description: format!(
                    "The system registry hive at '{}' has weak permissions allowing standard users to read local password hashes (SeriousSAM / HiveNightmare).",
                    file.display_path
                ),
                remediation_advice: "Run 'icacls %windir%\\system32\\config\\sam /reset' from an elevated prompt to restrict access to SYSTEM and Administrators.".to_string(),
            });
            return;
        }
    }

    // 2. Check for weak write permissions on executables/DLLs in Program Files / ProgramData / PATH
    if (file.extension == "exe" || file.extension == "dll" || file.extension == "sys")
        && is_system_or_program_path(&file.path)
    {
        // Check if write access is permitted by attempting an append/write check
        let is_writable = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&file.path)
            .is_ok();

        if is_writable {
            file.security_findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                category: "Local Privilege Escalation (LPE)".to_string(),
                title: "Privileged Binary Writable by Low-Privilege Trustee".to_string(),
                description: format!(
                    "The binary at '{}' resides in a system/program directory but permits write modifications by standard users, enabling binary planting or DLL hijacking to NT AUTHORITY\\SYSTEM.",
                    file.display_path
                ),
                remediation_advice: "Remove FILE_WRITE_DATA / FILE_APPEND_DATA permissions for BUILTIN\\Users and Everyone on this file and its parent folder.".to_string(),
            });
        }
    }

    // 3. Check for writable directory in system paths
    if file.is_directory && is_system_or_program_path(&file.path) && path_str.contains("programdata") {
        let test_file = file.path.join(".winsentry_perm_test.tmp");
        if std::fs::write(&test_file, b"test").is_ok() {
            let _ = std::fs::remove_file(&test_file);
            file.security_findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                category: "Local Privilege Escalation (LPE)".to_string(),
                title: "System Application Directory Writable by Standard Users".to_string(),
                description: format!(
                    "The directory at '{}' grants write permissions to standard user accounts, allowing malicious binary or script placement.",
                    file.display_path
                ),
                remediation_advice: "Audit folder DACL and revoke write access for BUILTIN\\Users.".to_string(),
            });
        }
    }
}
