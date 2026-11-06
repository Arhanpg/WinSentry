//! Win32 High-Velocity Kernel Traversal Engine
//!
//! Directly invokes `FindFirstFileExW` with `FindExInfoBasic` and `FIND_FIRST_EX_LARGE_FETCH`,
//! converts paths to `\\?\` extended syntax, guards against reparse point loops, and
//! prevents accidental cloud recall on OneDrive/iCloud placeholders.

use crate::models::{CleanTier, ScannedFile};
use crate::win32::storage::get_cluster_size_for_path;
use crate::win32::types::*;
use crate::win32::{filetime_to_unix_secs, from_wide_buf, strip_extended_prefix, to_extended_path, to_wide_chars};
use rayon::prelude::*;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

/// Discovered raw filesystem item during traversal
#[derive(Debug, Clone)]
pub struct RawDirEntry {
    pub path: PathBuf,
    pub file_name: String,
    pub attributes: u32,
    pub logical_size: u64,
    pub reparse_tag: u32,
    pub modified_timestamp: u64,
    pub is_directory: bool,
    pub is_reparse: bool,
    pub is_cloud_placeholder: bool,
}

/// Enumerates entries within a single directory using FindFirstFileExW + FIND_FIRST_EX_LARGE_FETCH
pub fn read_directory_fast<P: AsRef<Path>>(dir_path: P) -> (Vec<RawDirEntry>, Vec<PathBuf>) {
    let mut files = Vec::new();
    let mut subdirs = Vec::new();

    let ext_dir = to_extended_path(dir_path);
    let mut search_pattern = ext_dir.clone();
    search_pattern.push("*");

    let wide_pattern = to_wide_chars(search_pattern.as_os_str());
    let mut find_data = MaybeUninit::<WIN32_FIND_DATAW>::uninit();

    unsafe {
        let handle = FindFirstFileExW(
            wide_pattern.as_ptr(),
            FINDEX_INFO_LEVELS::FindExInfoBasic,
            find_data.as_mut_ptr(),
            FINDEX_SEARCH_OPS::FindExSearchNameMatch,
            std::ptr::null_mut(),
            FIND_FIRST_EX_LARGE_FETCH,
        );

        if handle == INVALID_HANDLE_VALUE {
            return (files, subdirs);
        }

        let mut data = find_data.assume_init();

        loop {
            let name = from_wide_buf(&data.cFileName);
            // Skip . and .. to avoid self-referential loops
            if name != "." && name != ".." {
                let attrs = data.dwFileAttributes;
                let is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
                let is_reparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                let reparse_tag = data.dwReserved0;
                let is_cloud = (attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_OFFLINE))
                    != 0;

                let size = ((data.nFileSizeHigh as u64) << 32) | (data.nFileSizeLow as u64);
                let mod_time = filetime_to_unix_secs(data.ftLastWriteTime);

                let mut item_path = ext_dir.clone();
                item_path.push(&name);

                let entry = RawDirEntry {
                    path: item_path.clone(),
                    file_name: name,
                    attributes: attrs,
                    logical_size: size,
                    reparse_tag,
                    modified_timestamp: mod_time,
                    is_directory: is_dir,
                    is_reparse,
                    is_cloud_placeholder: is_cloud,
                };

                if is_dir {
                    // Reparse cycle guard: Do not recurse into reparse points (symlinks/junctions)
                    if is_reparse {
                        files.push(entry);
                    } else {
                        subdirs.push(item_path);
                    }
                } else {
                    files.push(entry);
                }
            }

            if FindNextFileW(handle, &mut data) == 0 {
                break;
            }
        }

        FindClose(handle);
    }

    (files, subdirs)
}

/// Recursively traverses a target directory tree using work-stealing parallelism
pub fn traverse_tree_parallel<P: AsRef<Path>, F>(
    root_path: P,
    progress_callback: Option<F>,
) -> Vec<ScannedFile>
where
    F: Fn(usize) + Send + Sync + 'static,
{
    let root = to_extended_path(root_path);
    let counter = Arc::new(AtomicUsize::new(0));
    let cb = progress_callback.map(Arc::new);

    let cluster_size = get_cluster_size_for_path(&root);
    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let (root_files, root_subdirs) = read_directory_fast(&root);

    let mut all_raw_entries = root_files;
    let mut pending_dirs = root_subdirs;

    // Traverse directory trees with rayon parallel iterator
    while !pending_dirs.is_empty() {
        let current_batch = std::mem::take(&mut pending_dirs);
        let results: Vec<(Vec<RawDirEntry>, Vec<PathBuf>)> = current_batch
            .into_par_iter()
            .map(|dir| read_directory_fast(dir))
            .collect();

        for (mut entries, mut subdirs) in results {
            all_raw_entries.append(&mut entries);
            pending_dirs.append(&mut subdirs);
        }

        if let Some(ref callback) = cb {
            let total = all_raw_entries.len();
            counter.store(total, Ordering::Relaxed);
            callback(total);
        }
    }

    // Convert raw entries to ScannedFile models
    all_raw_entries
        .into_par_iter()
        .map(|raw| {
            let display_path = strip_extended_prefix(&raw.path);
            let ext = Path::new(&raw.file_name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            // Calculate physical cluster size
            let physical_size = if raw.is_cloud_placeholder {
                0
            } else if raw.logical_size == 0 {
                0
            } else {
                ((raw.logical_size + cluster_size - 1) / cluster_size) * cluster_size
            };

            let age_days = if now_unix > raw.modified_timestamp {
                ((now_unix - raw.modified_timestamp) / 86400) as u32
            } else {
                0
            };

            // Check if reparse target is broken
            let is_broken = if raw.is_reparse {
                std::fs::metadata(&raw.path).is_err()
            } else {
                false
            };

            ScannedFile {
                path: raw.path,
                display_path,
                file_name: raw.file_name,
                extension: ext,
                logical_size: raw.logical_size,
                physical_size,
                attributes: raw.attributes,
                is_directory: raw.is_directory,
                is_reparse_point: raw.is_reparse,
                is_broken_link: is_broken,
                reparse_tag: raw.reparse_tag,
                is_cloud_placeholder: raw.is_cloud_placeholder,
                has_alternate_data_streams: false,
                alternate_data_streams: Vec::new(),
                modified_timestamp: raw.modified_timestamp,
                age_days,
                prehash: None,
                blake3_hash: None,
                sha256_hash: None,
                perceptual_hash: None,
                clean_tier: CleanTier::Active,
                clean_category: None,
                security_findings: Vec::new(),
                authenticode_status: None,
                pe_version_info: None,
                is_in_reference_folder: false,
                locking_processes: Vec::new(),
            }
        })
        .collect()
}

/// Maps logical drive letters to underlying physical disk device IDs
pub fn map_drive_to_physical_disk(drive_letter: char) -> Option<u32> {
    let drive_str = format!("{}:", drive_letter);
    let wide_drive = to_wide_chars(&drive_str);
    let mut target_buf = [0u16; 512];

    unsafe {
        let ret = QueryDosDeviceW(wide_drive.as_ptr(), target_buf.as_mut_ptr(), 512);
        if ret == 0 {
            return None;
        }

        let target = from_wide_buf(&target_buf);
        // Typical device mapping: \Device\HarddiskVolume2
        if let Some(pos) = target.find("HarddiskVolume") {
            let num_str = &target[pos + 14..];
            if let Ok(vol_num) = num_str.trim().parse::<u32>() {
                return Some(vol_num);
            }
        }
    }
    None
}
