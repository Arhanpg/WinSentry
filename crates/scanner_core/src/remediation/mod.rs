//! Safe Remediation and Space Reclamation Engine
//!
//! Features:
//! - Windows Restart Manager (rstrtmgr.dll) active process lock detection
//! - Safe Recycle Bin disposal with Explorer Undo support (FOF_ALLOWUNDO)
//! - Quarantine staging directory relocation with metadata manifest
//! - NTFS Hardlink & Symlink deduplication
//! - High-velocity tree deletion via FILE_FLAG_DELETE_ON_CLOSE

#![allow(non_snake_case)]

use crate::win32::types::*;
use crate::win32::{from_wide_buf, to_extended_path, to_wide_chars};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Information about an active process locking a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLockInfo {
    pub process_id: u32,
    pub app_name: String,
    pub service_name: String,
    pub is_restartable: bool,
}

/// Queries the Windows Restart Manager for processes holding open handles to target files
pub fn check_process_locks<P: AsRef<Path>>(paths: &[P]) -> Vec<(PathBuf, Vec<ProcessLockInfo>)> {
    let mut results = Vec::new();
    if paths.is_empty() {
        return results;
    }

    unsafe {
        let mut session_handle: DWORD = 0;
        let mut session_key = [0u16; 64];

        let start_res = RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr());
        if start_res != 0 {
            return results;
        }

        for path in paths {
            let p_buf = path.as_ref().to_path_buf();
            let wide_path = to_wide_chars(to_extended_path(&p_buf).as_os_str());
            let path_ptrs = [wide_path.as_ptr()];

            let reg_res = RmRegisterResources(
                session_handle,
                1,
                path_ptrs.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            );

            if reg_res == 0 {
                let mut n_proc_info_needed: u32 = 0;
                let mut n_proc_info: u32 = 16;
                let mut proc_info: Vec<RM_PROCESS_INFO> = Vec::with_capacity(16);
                proc_info.set_len(16);
                let mut reboot_reasons: u32 = 0;

                let get_res = RmGetList(
                    session_handle,
                    &mut n_proc_info_needed,
                    &mut n_proc_info,
                    proc_info.as_mut_ptr(),
                    &mut reboot_reasons,
                );

                if get_res == 0 && n_proc_info > 0 {
                    let mut lock_list = Vec::new();
                    for i in 0..n_proc_info as usize {
                        let info = &proc_info[i];
                        let app_name = from_wide_buf(&info.strAppName);
                        let svc_name = from_wide_buf(&info.strServiceShortName);
                        lock_list.push(ProcessLockInfo {
                            process_id: info.Process.dwProcessId,
                            app_name,
                            service_name: svc_name,
                            is_restartable: info.bRestartable != 0,
                        });
                    }
                    results.push((p_buf, lock_list));
                }
            }
        }

        RmEndSession(session_handle);
    }

    results
}

/// Routes a file or directory safely to Windows $RECYCLE.BIN using SHFileOperationW with FOF_ALLOWUNDO
pub fn move_to_recycle_bin<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    if !p.exists() {
        return Err("File does not exist".to_string());
    }

    let abs_path = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let mut wide_str = to_wide_chars(abs_path.as_os_str());
    // SHFileOperation requires double null-termination
    wide_str.push(0);

    #[repr(C)]
    struct SHFILEOPSTRUCTW {
        hwnd: HANDLE,
        wFunc: u32,
        pFrom: LPCWSTR,
        pTo: LPCWSTR,
        fFlags: u16,
        fAnyOperationsAborted: BOOL,
        hNameMappings: LPVOID,
        lpszProgressTitle: LPCWSTR,
    }

    const FO_DELETE: u32 = 0x0003;
    const FOF_ALLOWUNDO: u16 = 0x0040;
    const FOF_NOCONFIRMATION: u16 = 0x0010;
    const FOF_SILENT: u16 = 0x0004;

    #[link(name = "shell32")]
    extern "system" {
        fn SHFileOperationW(lpFileOp: *mut SHFILEOPSTRUCTW) -> i32;
    }

    let mut op = SHFILEOPSTRUCTW {
        hwnd: std::ptr::null_mut(),
        wFunc: FO_DELETE,
        pFrom: wide_str.as_ptr(),
        pTo: std::ptr::null(),
        fFlags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT,
        fAnyOperationsAborted: 0,
        hNameMappings: std::ptr::null_mut(),
        lpszProgressTitle: std::ptr::null(),
    };

    unsafe {
        let res = SHFileOperationW(&mut op);
        if res == 0 && op.fAnyOperationsAborted == 0 {
            Ok(())
        } else {
            Err(format!("SHFileOperationW failed with code: {}", res))
        }
    }
}

/// Quarantine manifest record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub timestamp_utc: String,
    pub reason: String,
    pub blake3_hash: Option<String>,
}

/// Relocates a suspicious file to a secure quarantine staging directory
pub fn quarantine_file<P: AsRef<Path>, Q: AsRef<Path>>(
    file_path: P,
    quarantine_root: Q,
    reason: &str,
    blake3_hash: Option<&str>,
) -> Result<QuarantineRecord, String> {
    let source = file_path.as_ref();
    let q_root = quarantine_root.as_ref();

    fs::create_dir_all(q_root).map_err(|e| format!("Failed to create quarantine root: {}", e))?;

    let file_name = source
        .file_name()
        .ok_or_else(|| "Invalid file name".to_string())?
        .to_string_lossy();

    let target = q_root.join(format!("{}_{}.quarantine", file_name, std::process::id()));

    // Move file to quarantine
    fs::rename(source, &target).or_else(|_| {
        fs::copy(source, &target).and_then(|_| fs::remove_file(source))
    }).map_err(|e| format!("Failed to quarantine file: {}", e))?;

    let record = QuarantineRecord {
        original_path: source.to_path_buf(),
        quarantined_path: target,
        timestamp_utc: chrono_free_timestamp(),
        reason: reason.to_string(),
        blake3_hash: blake3_hash.map(|s| s.to_string()),
    };

    // Save manifest record
    let manifest_path = q_root.join("quarantine_manifest.jsonl");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&manifest_path) {
        if let Ok(line) = serde_json::to_string(&record) {
            let _ = writeln!(f, "{}", line);
        }
    }

    Ok(record)
}

/// Replaces a duplicate file with an NTFS Hardlink to the master file
pub fn hardlink_duplicate<P: AsRef<Path>, M: AsRef<Path>>(
    duplicate_path: P,
    master_path: M,
) -> Result<(), String> {
    let dup = duplicate_path.as_ref();
    let master = master_path.as_ref();

    let ext_dup = to_extended_path(dup);
    let ext_master = to_extended_path(master);

    let wide_dup = to_wide_chars(ext_dup.as_os_str());
    let wide_master = to_wide_chars(ext_master.as_os_str());

    // Remove duplicate before linking
    let temp_name = dup.with_extension("winsentry_hl_tmp");
    fs::rename(dup, &temp_name).map_err(|e| format!("Failed to rename duplicate: {}", e))?;

    unsafe {
        let success = CreateHardLinkW(wide_dup.as_ptr(), wide_master.as_ptr(), std::ptr::null_mut());
        if success != 0 {
            let _ = fs::remove_file(&temp_name);
            Ok(())
        } else {
            // Restore duplicate on failure
            let _ = fs::rename(&temp_name, dup);
            Err("CreateHardLinkW failed across volumes or unprivileged context".to_string())
        }
    }
}

/// Fast kernel-level deletion of large directory trees via FILE_FLAG_DELETE_ON_CLOSE
pub fn fast_delete_file_or_dir<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    let ext_path = to_extended_path(p);
    let wide_path = to_wide_chars(ext_path.as_os_str());

    unsafe {
        let handle = CreateFileW(
            wide_path.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );

        if handle != INVALID_HANDLE_VALUE {
            CloseHandle(handle);
            Ok(())
        } else {
            // Fallback to standard standard library removal
            if p.is_dir() {
                fs::remove_dir_all(p).map_err(|e| e.to_string())
            } else {
                fs::remove_file(p).map_err(|e| e.to_string())
            }
        }
    }
}

fn chrono_free_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or_default();
    format!("UnixSecs-{}", duration.as_secs())
}
