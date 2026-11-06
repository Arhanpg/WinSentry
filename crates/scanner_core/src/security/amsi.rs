//! Dynamic Script Inspection via Windows Antimalware Scan Interface (AMSI)
//!
//! Submits script buffers (.ps1, .vbs, .js, macros) to the Windows antimalware
//! provider (amsi.dll). Traps HRESULT 0x80070015 (ERROR_NOT_READY) when
//! Defender Real-Time Protection is turned off.

#![allow(non_snake_case)]

use crate::models::{ScannedFile, SecurityFinding, SecuritySeverity};
use crate::win32::to_wide_chars;
use crate::win32::types::*;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;

// Dynamic function pointer signatures for amsi.dll
type FnAmsiInitialize = unsafe extern "system" fn(appName: LPCWSTR, amsiContext: *mut HAMSICONTEXT) -> HRESULT;
type FnAmsiOpenSession = unsafe extern "system" fn(amsiContext: HAMSICONTEXT, amsiSession: *mut HAMSISESSION) -> HRESULT;
type FnAmsiScanBuffer = unsafe extern "system" fn(
    amsiContext: HAMSICONTEXT,
    buffer: *const c_void,
    length: ULONG, // 32-bit ULONG ABI
    contentName: LPCWSTR,
    amsiSession: HAMSISESSION,
    result: *mut AMSI_RESULT,
) -> HRESULT;
type FnAmsiCloseSession = unsafe extern "system" fn(amsiContext: HAMSICONTEXT, amsiSession: HAMSISESSION);
type FnAmsiUninitialize = unsafe extern "system" fn(amsiContext: HAMSICONTEXT);

extern "system" {
    fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HANDLE;
    fn GetProcAddress(hModule: HANDLE, lpProcName: *const u8) -> *mut c_void;
}

pub struct AmsiScanner {
    _hmodule: HANDLE,
    amsi_context: HAMSICONTEXT,
    fn_open_session: FnAmsiOpenSession,
    fn_scan_buffer: FnAmsiScanBuffer,
    fn_close_session: FnAmsiCloseSession,
    fn_uninitialize: FnAmsiUninitialize,
}

// Send and Sync implementations for thread-safe scanning
unsafe impl Send for AmsiScanner {}
unsafe impl Sync for AmsiScanner {}

impl AmsiScanner {
    /// Initializes an AMSI scanning session
    pub fn new() -> Option<Self> {
        let dll_name = to_wide_chars("amsi.dll");
        unsafe {
            let hmodule = LoadLibraryW(dll_name.as_ptr());
            if hmodule.is_null() || hmodule == INVALID_HANDLE_VALUE {
                return None;
            }

            let fn_init: FnAmsiInitialize = std::mem::transmute(GetProcAddress(hmodule, b"AmsiInitialize\0".as_ptr()));
            let fn_open: FnAmsiOpenSession = std::mem::transmute(GetProcAddress(hmodule, b"AmsiOpenSession\0".as_ptr()));
            let fn_scan: FnAmsiScanBuffer = std::mem::transmute(GetProcAddress(hmodule, b"AmsiScanBuffer\0".as_ptr()));
            let fn_close: FnAmsiCloseSession = std::mem::transmute(GetProcAddress(hmodule, b"AmsiCloseSession\0".as_ptr()));
            let fn_uninit: FnAmsiUninitialize = std::mem::transmute(GetProcAddress(hmodule, b"AmsiUninitialize\0".as_ptr()));

            let app_name = to_wide_chars("WinSentry-SecurityAuditor");
            let mut context: HAMSICONTEXT = std::ptr::null_mut();

            let hr = fn_init(app_name.as_ptr(), &mut context);
            if hr != 0 || context.is_null() {
                return None;
            }

            Some(Self {
                _hmodule: hmodule,
                amsi_context: context,
                fn_open_session: fn_open,
                fn_scan_buffer: fn_scan,
                fn_close_session: fn_close,
                fn_uninitialize: fn_uninit,
            })
        }
    }

    /// Scans a byte buffer with AMSI
    pub fn scan_buffer(&self, buffer: &[u8], content_name: &str) -> Result<AMSI_RESULT, HRESULT> {
        let wide_name = to_wide_chars(content_name);
        let mut session: HAMSISESSION = std::ptr::null_mut();
        let mut result = AMSI_RESULT::AMSI_RESULT_NOT_DETECTED;

        unsafe {
            let hr_session = (self.fn_open_session)(self.amsi_context, &mut session);
            if hr_session != 0 {
                return Err(hr_session);
            }

            // Note: ULONG is 32-bit per Win32 ABI requirement
            let len = buffer.len() as ULONG;
            let hr_scan = (self.fn_scan_buffer)(
                self.amsi_context,
                buffer.as_ptr() as *const c_void,
                len,
                wide_name.as_ptr(),
                session,
                &mut result,
            );

            (self.fn_close_session)(self.amsi_context, session);

            if hr_scan != 0 {
                Err(hr_scan)
            } else {
                Ok(result)
            }
        }
    }
}

impl Drop for AmsiScanner {
    fn drop(&mut self) {
        if !self.amsi_context.is_null() {
            unsafe {
                (self.fn_uninitialize)(self.amsi_context);
            }
        }
    }
}

/// Audits script files (.ps1, .vbs, .js, .bat, .cmd) via AMSI
pub fn audit_file_with_amsi(
    file: &mut ScannedFile,
    amsi_scanner: Option<&AmsiScanner>,
    defender_offline_alerted: &mut bool,
) {
    let script_exts = ["ps1", "vbs", "js", "jse", "vbe", "wsf", "hta", "bat", "cmd"];
    if !script_exts.contains(&file.extension.as_str()) {
        return;
    }

    let scanner = match amsi_scanner {
        Some(s) => s,
        None => return,
    };

    // Read up to 2 MB of script content
    let mut buffer = Vec::new();
    if let Ok(f) = File::open(&file.path) {
        let mut take = f.take(2 * 1024 * 1024);
        if take.read_to_end(&mut buffer).is_err() || buffer.is_empty() {
            return;
        }
    } else {
        return;
    }

    match scanner.scan_buffer(&buffer, &file.file_name) {
        Ok(result) => {
            if amsi_result_is_malware(result) {
                file.security_findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    category: "Dynamic Script Malware (AMSI)".to_string(),
                    title: "Malicious Obfuscated Script Detected by AMSI".to_string(),
                    description: format!(
                        "Windows Antimalware Scan Interface (AMSI) flagged '{}' as malicious script payload.",
                        file.display_path
                    ),
                    remediation_advice: "Quarantine or safely delete immediately with WinSentry clean --quarantine.".to_string(),
                });
            }
        }
        Err(hr) => {
            // Check for HRESULT 0x80070015 (ERROR_NOT_READY: Real-Time Protection is turned off)
            if hr == -2147024875 || (hr as u32) == 0x80070015 {
                if !*defender_offline_alerted {
                    *defender_offline_alerted = true;
                    file.security_findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        category: "Endpoint Protection Warning".to_string(),
                        title: "Microsoft Defender Real-Time Protection is Disabled".to_string(),
                        description: "AmsiScanBuffer returned HRESULT 0x80070015 (ERROR_NOT_READY). Windows Defender real-time scanning is currently turned off on this system.".to_string(),
                        remediation_advice: "Enable Real-Time Protection in Windows Security Center -> Virus & threat protection settings.".to_string(),
                    });
                }
            }
        }
    }
}
