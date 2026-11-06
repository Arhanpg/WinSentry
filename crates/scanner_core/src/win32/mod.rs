//! Win32 Abstractions and Utilities
//!
//! Provides path normalization (supporting extended paths up to 32,767 chars via `\\?\`),
//! string encoding conversions, and core safe wrappers.

pub mod storage;
pub mod traversal;
pub mod types;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Normalizes a path to the Win32 extended-length format `\\?\` to bypass MAX_PATH (260 chars)
/// and support paths up to 32,767 characters. Handles UNC paths (`\\?\UNC\...`) seamlessly.
pub fn to_extended_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    let s = path.to_string_lossy();

    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return path.to_path_buf();
    }

    if s.starts_with(r"\\") {
        // UNC path: \\server\share -> \\?\UNC\server\share
        let stripped = &s[2..];
        PathBuf::from(format!(r"\\?\UNC\{}", stripped))
    } else {
        // Local path: C:\path -> \\?\C:\path
        if let Ok(abs) = std::fs::canonicalize(path) {
            let abs_str = abs.to_string_lossy();
            if abs_str.starts_with(r"\\?\") {
                return abs;
            }
            return PathBuf::from(format!(r"\\?\{}", abs_str.trim_start_matches(r"\??\")));
        }
        PathBuf::from(format!(r"\\?\{}", s))
    }
}

/// Strips the `\\?\` or `\\?\UNC\` prefix for clean user-facing presentation.
pub fn strip_extended_prefix<P: AsRef<Path>>(path: P) -> String {
    let s = path.as_ref().to_string_lossy().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", rest)
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s
    }
}

/// Encodes an OsStr or Path to a null-terminated UTF-16 wide string (`Vec<u16>`).
pub fn to_wide_chars<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Decodes a null-terminated UTF-16 slice into a Rust String.
pub fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// Decodes a fixed-size UTF-16 buffer with null termination into a Rust String.
pub fn from_wide_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Converts Win32 FILETIME into a 64-bit Unix timestamp in seconds.
pub fn filetime_to_unix_secs(ft: types::FILETIME) -> u64 {
    let intervals = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    // 100-nanosecond intervals between Jan 1, 1601 and Jan 1, 1970
    const EPOCH_DIFFERENCE: u64 = 116444736000000000;
    if intervals >= EPOCH_DIFFERENCE {
        (intervals - EPOCH_DIFFERENCE) / 10_000_000
    } else {
        0
    }
}
