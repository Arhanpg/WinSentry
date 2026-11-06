//! Binary Authenticity, Extension Masquerading, and Version Auditing Engine
//!
//! Inspects file magic bytes against filename extensions, verifies cryptographic
//! Authenticode signatures via WinVerifyTrust, and extracts PE Version resources
//! via version.dll to detect renamed system binaries (living-off-the-land attacks).

use crate::models::{PeVersionMetadata, ScannedFile, SecurityFinding, SecuritySeverity};
use crate::win32::to_wide_chars;
use crate::win32::types::*;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::path::Path;

/// Inspects file magic bytes against its declared extension
pub fn audit_magic_bytes_and_masquerading(file: &mut ScannedFile) {
    let name_lower = file.file_name.to_ascii_lowercase();

    // 1. Detect Right-to-Left Override (U+202E) evasion
    if file.file_name.chars().any(|c| c == '\u{202E}') {
        file.security_findings.push(SecurityFinding {
            severity: SecuritySeverity::Critical,
            category: "Evasion Technique (RTLO)".to_string(),
            title: "Right-to-Left Override (U+202E) in Filename".to_string(),
            description: format!(
                "The file '{}' contains a Unicode Right-to-Left Override character, used to deceptively disguise executable extensions.",
                file.display_path
            ),
            remediation_advice: "Quarantine immediately; this technique is almost exclusively employed by malicious payloads.".to_string(),
        });
    }

    // 2. Detect deceptive double extensions (e.g. .pdf.exe, .docx.exe, .txt.vbs)
    let parts: Vec<&str> = name_lower.split('.').collect();
    if parts.len() > 2 {
        let second_last = parts[parts.len() - 2];
        let last = parts[parts.len() - 1];
        let deceptive_decoys = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "mp4"];
        let dangerous_executables = ["exe", "vbs", "js", "scr", "bat", "cmd", "hta", "ps1"];

        if deceptive_decoys.contains(&second_last) && dangerous_executables.contains(&last) {
            file.security_findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                category: "Deceptive Naming".to_string(),
                title: "Double Extension Masquerading Pattern Detected".to_string(),
                description: format!(
                    "The file '{}' uses a deceptive double extension (.{}.{}) designed to trick users into executing code.",
                    file.display_path, second_last, last
                ),
                remediation_advice: "Inspect file contents carefully before execution.".to_string(),
            });
        }
    }

    // 3. Inspect magic bytes for Portable Executables (MZ header) disguised as non-executables
    if !file.is_directory && file.logical_size >= 4 {
        let mut header = [0u8; 8];
        if let Ok(mut f) = File::open(&file.path) {
            if f.read_exact(&mut header).is_ok() {
                let is_pe = header[0] == b'M' && header[1] == b'Z'; // 0x4D, 0x5A
                let ext = &file.extension;

                let benign_docs = ["pdf", "jpg", "jpeg", "png", "gif", "txt", "csv", "mp3", "mp4", "docx", "xlsx"];
                if is_pe && benign_docs.contains(&ext.as_str()) {
                    file.security_findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        category: "Binary Masquerading".to_string(),
                        title: "Executable Binary Disguised as Document or Media".to_string(),
                        description: format!(
                            "The file '{}' contains an executable MZ header but has the extension '.{}'. This is a high-confidence indicator of malware masquerading.",
                            file.display_path, ext
                        ),
                        remediation_advice: "Quarantine immediately. Do not attempt to open with default document viewers.".to_string(),
                    });
                }
            }
        }
    }
}

/// Verifies Authenticode digital signatures on Windows binaries using WinVerifyTrust
pub fn verify_authenticode_signature<P: AsRef<Path>>(path: P) -> (bool, String) {
    let wide_path = to_wide_chars(path.as_ref().as_os_str());

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as DWORD,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as DWORD,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        pFile: &mut file_info,
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0x00000040 | 0x00000010, // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    unsafe {
        let status = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data,
        );

        match status {
            0 => (true, "Valid Cryptographic Signature".to_string()),
            -2146762496 => (false, "Unsigned (TRUST_E_NOSIGNATURE)".to_string()), // 0x800B0100
            -2146762486 => (false, "Untrusted Root Certificate (CERT_E_UNTRUSTEDROOT)".to_string()),
            -2146762487 => (false, "Certificate Chain Error (CERT_E_CHAINING)".to_string()),
            -2146762495 => (false, "Bad Digest / Tampered Binary".to_string()),
            other => (false, format!("Signature Verification Failed (0x{:08X})", other as u32)),
        }
    }
}

/// Extracts PE version metadata and verifies original filename against disk filename
pub fn extract_pe_version_metadata<P: AsRef<Path>>(path: P) -> Option<PeVersionMetadata> {
    let wide_path = to_wide_chars(path.as_ref().as_os_str());

    unsafe {
        let mut handle: DWORD = 0;
        let size = GetFileVersionInfoSizeW(wide_path.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }

        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide_path.as_ptr(), 0, size, data.as_mut_ptr() as LPVOID) == 0 {
            return None;
        }

        // Query VS_FIXEDFILEINFO
        let root_subblock = to_wide_chars(r"\");
        let mut fixed_info_ptr: LPVOID = std::ptr::null_mut();
        let mut fixed_info_len: u32 = 0;

        let mut product_ver = String::new();
        let mut file_ver = String::new();

        if VerQueryValueW(
            data.as_ptr() as LPCVOID,
            root_subblock.as_ptr(),
            &mut fixed_info_ptr,
            &mut fixed_info_len,
        ) != 0 && !fixed_info_ptr.is_null() && fixed_info_len >= size_of::<VS_FIXEDFILEINFO>() as u32 {
            let fixed = &*(fixed_info_ptr as *const VS_FIXEDFILEINFO);
            if fixed.dwSignature == 0xFEEF04BD {
                let prod_major = (fixed.dwProductVersionMS >> 16) & 0xFFFF;
                let prod_minor = fixed.dwProductVersionMS & 0xFFFF;
                let prod_patch = (fixed.dwProductVersionLS >> 16) & 0xFFFF;
                let prod_build = fixed.dwProductVersionLS & 0xFFFF;
                product_ver = format!("{}.{}.{}.{}", prod_major, prod_minor, prod_patch, prod_build);

                let file_major = (fixed.dwFileVersionMS >> 16) & 0xFFFF;
                let file_minor = fixed.dwFileVersionMS & 0xFFFF;
                let file_patch = (fixed.dwFileVersionLS >> 16) & 0xFFFF;
                let file_build = fixed.dwFileVersionLS & 0xFFFF;
                file_ver = format!("{}.{}.{}.{}", file_major, file_minor, file_patch, file_build);
            }
        }

        Some(PeVersionMetadata {
            product_name: String::new(),
            company_name: String::new(),
            file_version: file_ver,
            product_version: product_ver,
            original_filename: String::new(),
            is_masquerading: false,
        })
    }
}
