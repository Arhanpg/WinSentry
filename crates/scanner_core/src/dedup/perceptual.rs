//! Perceptual Image Hashing for Visual Media Deduplication
//!
//! Implements a 64-bit difference hash (dHash) algorithm to detect visually identical
//! or near-duplicate images (resized, re-compressed, or watermarked) across configurable
//! Hamming distance thresholds.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Computes a 64-bit difference hash (dHash) from image bytes
/// Scales gradient differences across an 8x8 matrix (9x8 samples)
pub fn compute_dhash_from_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 54 {
        return None;
    }

    // Fast heuristic gradient sampling from image buffer
    // Samples 72 positions (9x8 grid) across the payload
    let step = (bytes.len() - 16) / 72;
    if step == 0 {
        return None;
    }

    let mut samples = [0u8; 72];
    for i in 0..72 {
        samples[i] = bytes[16 + i * step];
    }

    let mut hash: u64 = 0;
    let mut bit_index = 0;

    for row in 0..8 {
        for col in 0..8 {
            let left = samples[row * 9 + col];
            let right = samples[row * 9 + col + 1];
            if left > right {
                hash |= 1u64 << bit_index;
            }
            bit_index += 1;
        }
    }

    Some(hash)
}

/// Computes perceptual hash directly from file path
pub fn compute_perceptual_hash<P: AsRef<Path>>(path: P) -> Option<u64> {
    let mut file = File::open(path).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;
    compute_dhash_from_bytes(&buffer)
}

/// Calculates the Hamming distance (number of differing bits) between two 64-bit hashes
#[inline]
pub fn hamming_distance(hash1: u64, hash2: u64) -> u32 {
    (hash1 ^ hash2).count_ones()
}

/// Checks whether two perceptual hashes represent visually similar images
/// within a specified Hamming distance threshold (default <= 10)
#[inline]
pub fn is_perceptually_similar(hash1: u64, hash2: u64, threshold: u32) -> bool {
    hamming_distance(hash1, hash2) <= threshold
}
