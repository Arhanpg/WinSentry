//! Win32 Precision Cluster Accounting and Alternate Data Stream (ADS) Engine
//!
//! Queries NTFS sectors-per-cluster via `GetDiskFreeSpaceW`, handles compressed
//! and sparse file physical allocations via `GetCompressedFileSizeW`, and
//! inspects secondary Alternate Data Streams via `FindFirstStreamW`.

use crate::win32::types::*;
use crate::win32::{from_wide_buf, to_extended_path, to_wide_chars};
use std::mem::MaybeUninit;
use std::path::Path;

/// Default NTFS cluster size (4 KB) used as fallback
pub const DEFAULT_CLUSTER_SIZE: u64 = 4096;

/// Retrieves the cluster size (in bytes) for the volume containing the specified path
pub fn get_cluster_size_for_path<P: AsRef<Path>>(path: P) -> u64 {
    let path = path.as_ref();
    let abs_path = if let Ok(canon) = std::fs::canonicalize(path) {
        canon
    } else {
        path.to_path_buf()
    };

    let path_str = abs_path.to_string_lossy();
    let root = if path_str.len() >= 3 && path_str.chars().nth(1) == Some(':') {
        format!("{}:\\", path_str.chars().next().unwrap())
    } else {
        r"C:\".to_string()
    };

    let wide_root = to_wide_chars(&root);
    let mut sectors_per_cluster: DWORD = 0;
    let mut bytes_per_sector: DWORD = 0;
    let mut free_clusters: DWORD = 0;
    let mut total_clusters: DWORD = 0;

    unsafe {
        let success = GetDiskFreeSpaceW(
            wide_root.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        );

        if success != 0 && sectors_per_cluster > 0 && bytes_per_sector > 0 {
            (sectors_per_cluster as u64) * (bytes_per_sector as u64)
        } else {
            DEFAULT_CLUSTER_SIZE
        }
    }
}

/// Computes the exact physical size of a file, taking into account compressed or sparse attributes
pub fn get_exact_physical_size<P: AsRef<Path>>(path: P, logical_size: u64, attributes: u32, cluster_size: u64) -> u64 {
    if (attributes & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_OFFLINE)) != 0 {
        return 0;
    }

    if logical_size == 0 {
        return 0;
    }

    // For compressed or sparse files, invoke GetCompressedFileSizeW
    if (attributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)) != 0 {
        let ext_path = to_extended_path(path);
        let wide_path = to_wide_chars(ext_path.as_os_str());
        let mut high_size: DWORD = 0;

        unsafe {
            let low_size = GetCompressedFileSizeW(wide_path.as_ptr(), &mut high_size);
            if low_size != 0xFFFFFFFF || high_size != 0 {
                return ((high_size as u64) << 32) | (low_size as u64);
            }
        }
    }

    // Standard cluster alignment
    let effective_cluster = if cluster_size == 0 { DEFAULT_CLUSTER_SIZE } else { cluster_size };
    ((logical_size + effective_cluster - 1) / effective_cluster) * effective_cluster
}

/// Inspects Alternate Data Streams (ADS) for a given file
pub fn inspect_alternate_data_streams<P: AsRef<Path>>(path: P) -> Vec<(String, u64)> {
    let mut streams = Vec::new();
    let ext_path = to_extended_path(path);
    let wide_path = to_wide_chars(ext_path.as_os_str());

    let mut stream_data = MaybeUninit::<WIN32_FIND_STREAM_DATA>::uninit();

    unsafe {
        let handle = FindFirstStreamW(
            wide_path.as_ptr(),
            STREAM_INFO_LEVELS::FindStreamInfoStandard,
            stream_data.as_mut_ptr(),
            0,
        );

        if handle == INVALID_HANDLE_VALUE {
            return streams;
        }

        let mut data = stream_data.assume_init();

        loop {
            let stream_name = from_wide_buf(&data.cStreamName);
            // Default unnamed data stream is "::$DATA"
            if !stream_name.is_empty() && stream_name != "::$DATA" {
                let size = if data.StreamSize >= 0 { data.StreamSize as u64 } else { 0 };
                streams.push((stream_name, size));
            }

            if FindNextStreamW(handle, &mut data) == 0 {
                break;
            }
        }

        FindClose(handle);
    }

    streams
}
