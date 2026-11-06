//! Comprehensive Unit and Integration Tests for WinSentry Core Engine

use scanner_core::cache::ScanCache;
use scanner_core::classifier::{is_build_tree, is_graphics_or_os_staging, is_package_cache};
use scanner_core::dedup::perceptual::{compute_dhash_from_bytes, hamming_distance, is_perceptually_similar};
use scanner_core::dedup::{compute_edge_prehash, compute_full_hashes, find_duplicates};
use scanner_core::models::{CleanTier, ScannedFile};
use scanner_core::security::authenticity::audit_magic_bytes_and_masquerading;
use scanner_core::security::signatures::{audit_hash_intelligence, audit_static_patterns, eicar_sha256, get_known_good_hashes};
use scanner_core::win32::storage::get_exact_physical_size;
use scanner_core::win32::traversal::traverse_tree_parallel;
use scanner_core::win32::{strip_extended_prefix, to_extended_path};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_path_normalization() {
    let p = PathBuf::from(r"C:\Windows\System32");
    let ext = to_extended_path(&p);
    assert!(ext.to_string_lossy().starts_with(r"\\?\"));

    let stripped = strip_extended_prefix(&ext);
    assert_eq!(stripped, r"C:\Windows\System32");

    let unc = PathBuf::from(r"\\server\share\folder");
    let ext_unc = to_extended_path(&unc);
    assert!(ext_unc.to_string_lossy().starts_with(r"\\?\UNC\"));
    let stripped_unc = strip_extended_prefix(&ext_unc);
    assert_eq!(stripped_unc, r"\\server\share\folder");
}

#[test]
fn test_cluster_physical_sizing() {
    const CLUSTER_SIZE: u64 = 4096;

    // 0 bytes -> 0 physical
    assert_eq!(get_exact_physical_size("test", 0, 0, CLUSTER_SIZE), 0);

    // 1 byte -> 1 cluster (4096)
    assert_eq!(get_exact_physical_size("test", 1, 0, CLUSTER_SIZE), 4096);

    // 4096 bytes -> 4096 bytes
    assert_eq!(get_exact_physical_size("test", 4096, 0, CLUSTER_SIZE), 4096);

    // 4097 bytes -> 2 clusters (8192)
    assert_eq!(get_exact_physical_size("test", 4097, 0, CLUSTER_SIZE), 8192);

    // Cloud placeholder attribute -> 0 bytes
    assert_eq!(get_exact_physical_size("test", 10_000_000, 0x00400000, CLUSTER_SIZE), 0);
}

#[test]
fn test_heuristic_classification_rules() {
    assert!(is_package_cache(r"c:\users\user\appdata\local\npm\_cacache\content-v2").is_some());
    assert!(is_package_cache(r"c:\users\user\appdata\local\pip\cache\wheels").is_some());
    assert!(is_package_cache(r"c:\users\user\appdata\local\uv\cache").is_some());

    assert!(is_graphics_or_os_staging(r"c:\users\user\appdata\local\dxcache", "bin").is_some());
    assert!(is_graphics_or_os_staging(r"c:\temp\app.tmp", "tmp").is_some());
    assert!(is_graphics_or_os_staging(r"c:\dumps\crash.dmp", "dmp").is_some());

    assert!(is_build_tree(r"d:\project\target\debug\deps").is_some());
    assert!(is_build_tree(r"d:\project\node_modules\lodash").is_some());
    assert!(is_build_tree(r"d:\project\.venv\lib\site-packages").is_some());
}

#[test]
fn test_two_stage_deduplication() {
    let temp_dir = std::env::temp_dir().join(format!("winsentry_test_dedup_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let payload = b"WinSentry Production Test Cryptographic Deduplication Payload 1234567890";
    let file1 = temp_dir.join("file1.bin");
    let file2 = temp_dir.join("file2.bin");
    let file3 = temp_dir.join("unique.bin");

    fs::write(&file1, payload).unwrap();
    fs::write(&file2, payload).unwrap();
    fs::write(&file3, b"Different unique payload").unwrap();

    let pre1 = compute_edge_prehash(&file1, payload.len() as u64).unwrap();
    let pre2 = compute_edge_prehash(&file2, payload.len() as u64).unwrap();
    assert_eq!(pre1, pre2);

    let (b3_1, sha_1) = compute_full_hashes(&file1).unwrap();
    let (b3_2, sha_2) = compute_full_hashes(&file2).unwrap();
    assert_eq!(b3_1, b3_2);
    assert_eq!(sha_1, sha_2);

    let mut scanned = traverse_tree_parallel(&temp_dir, None::<fn(usize)>);
    assert!(scanned.len() >= 3);

    let dup_groups = find_duplicates(&mut scanned, 1, &[]);
    assert_eq!(dup_groups.len(), 1);
    assert_eq!(dup_groups[0].files.len(), 2);
    assert_eq!(dup_groups[0].file_size, payload.len() as u64);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_reference_folder_protection() {
    let temp_dir = std::env::temp_dir().join(format!("winsentry_test_ref_{}", std::process::id()));
    let ref_dir = temp_dir.join("MasterArchive");
    let target_dir = temp_dir.join("Downloads");
    fs::create_dir_all(&ref_dir).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    let payload = b"Identical Duplicate across Reference Folder and Target Folder";
    let master_file = ref_dir.join("master.dat");
    let copy_file = target_dir.join("downloaded_copy.dat");

    fs::write(&master_file, payload).unwrap();
    fs::write(&copy_file, payload).unwrap();

    let mut scanned = traverse_tree_parallel(&temp_dir, None::<fn(usize)>);
    let dup_groups = find_duplicates(&mut scanned, 1, &[ref_dir.clone()]);

    assert_eq!(dup_groups.len(), 1);
    let group = &dup_groups[0];

    // Verify master copy is flagged as protected reference
    let ext_ref = to_extended_path(&ref_dir);
    let ext_target = to_extended_path(&target_dir);

    let master_in_group = group.files.iter().find(|f| f.path.starts_with(&ext_ref)).unwrap();
    assert!(master_in_group.is_in_reference_folder);

    let copy_in_group = group.files.iter().find(|f| f.path.starts_with(&ext_target)).unwrap();
    assert!(!copy_in_group.is_in_reference_folder);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_perceptual_image_hashing() {
    let image_bytes_a = vec![128u8; 100];
    let mut image_bytes_b = vec![128u8; 100];
    image_bytes_b[30] = 130; // slight difference

    let hash_a = compute_dhash_from_bytes(&image_bytes_a).unwrap();
    let hash_b = compute_dhash_from_bytes(&image_bytes_b).unwrap();

    let dist = hamming_distance(hash_a, hash_b);
    assert!(is_perceptually_similar(hash_a, hash_b, 10));
    assert!(dist <= 10);
}

#[test]
fn test_security_masquerading_and_rtlo() {
    let mut file = ScannedFile {
        path: PathBuf::from("test\u{202E}fdp.exe"),
        display_path: "test\u{202E}fdp.exe".to_string(),
        file_name: "test\u{202E}fdp.exe".to_string(),
        extension: "exe".to_string(),
        logical_size: 100,
        physical_size: 4096,
        attributes: 0,
        is_directory: false,
        is_reparse_point: false,
        is_broken_link: false,
        reparse_tag: 0,
        is_cloud_placeholder: false,
        has_alternate_data_streams: false,
        alternate_data_streams: Vec::new(),
        modified_timestamp: 0,
        age_days: 0,
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
    };

    audit_magic_bytes_and_masquerading(&mut file);
    assert!(file.security_findings.iter().any(|f| f.category.contains("RTLO")));

    // Test double extension masquerading
    file.file_name = "invoice.pdf.exe".to_string();
    audit_magic_bytes_and_masquerading(&mut file);
    assert!(file.security_findings.iter().any(|f| f.category.contains("Deceptive Naming")));
}

#[test]
fn test_security_static_patterns_and_secrets() {
    let temp_dir = std::env::temp_dir().join(format!("winsentry_test_sec_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let secret_file = temp_dir.join("config.env");
    let content = format!("AWS_ACCESS_KEY_ID={}{}\n# Secret Key\n", "AKIA", "IOSFODNN7EXAMPLE");
    fs::write(&secret_file, &content).unwrap();

    let mut file = ScannedFile {
        path: secret_file.clone(),
        display_path: secret_file.to_string_lossy().to_string(),
        file_name: "config.env".to_string(),
        extension: "env".to_string(),
        logical_size: content.len() as u64,
        physical_size: 4096,
        attributes: 0,
        is_directory: false,
        is_reparse_point: false,
        is_broken_link: false,
        reparse_tag: 0,
        is_cloud_placeholder: false,
        has_alternate_data_streams: false,
        alternate_data_streams: Vec::new(),
        modified_timestamp: 0,
        age_days: 0,
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
    };

    audit_static_patterns(&mut file);
    assert!(file.security_findings.iter().any(|f| f.title.contains("AWS Access Key")));

    // Test EICAR hash check
    file.sha256_hash = Some(eicar_sha256());
    let known_good = get_known_good_hashes();
    audit_hash_intelligence(&mut file, &known_good);
    assert!(file.security_findings.iter().any(|f| f.title.contains("EICAR")));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_crash_resilient_cache_integrity() {
    let temp_cache = std::env::temp_dir().join(format!("winsentry_test_cache_{}.json", std::process::id()));

    let mut cache = ScanCache::new();
    let file = ScannedFile {
        path: PathBuf::from(r"C:\test\sample.txt"),
        display_path: r"C:\test\sample.txt".to_string(),
        file_name: "sample.txt".to_string(),
        extension: "txt".to_string(),
        logical_size: 1024,
        physical_size: 4096,
        attributes: 0,
        is_directory: false,
        is_reparse_point: false,
        is_broken_link: false,
        reparse_tag: 0,
        is_cloud_placeholder: false,
        has_alternate_data_streams: false,
        alternate_data_streams: Vec::new(),
        modified_timestamp: 1700000000,
        age_days: 10,
        prehash: Some("prehash123".to_string()),
        blake3_hash: Some("b3hash123".to_string()),
        sha256_hash: Some("sha123".to_string()),
        perceptual_hash: None,
        clean_tier: CleanTier::Safe,
        clean_category: None,
        security_findings: Vec::new(),
        authenticode_status: None,
        pe_version_info: None,
        is_in_reference_folder: false,
        locking_processes: Vec::new(),
    };

    cache.record_file(&file);
    cache.save_to_file(&temp_cache).unwrap();

    // Reload and verify
    let loaded = ScanCache::load_from_file(&temp_cache);
    assert_eq!(loaded.entries.len(), 1);
    let entry = loaded.entries.get(&PathBuf::from(r"C:\test\sample.txt")).unwrap();
    assert_eq!(entry.file_size, 1024);
    assert_eq!(entry.blake3_hash.as_deref(), Some("b3hash123"));

    // Simulate corrupted file state (tampering payload without updating checksum)
    let mut raw_bytes = fs::read(&temp_cache).unwrap();
    raw_bytes.push(b'X'); // corrupt payload
    fs::write(&temp_cache, raw_bytes).unwrap();

    let safe_reloaded = ScanCache::load_from_file(&temp_cache);
    // Should gracefully reset without panic or crash
    assert_eq!(safe_reloaded.entries.len(), 0);

    let _ = fs::remove_file(&temp_cache);
}
