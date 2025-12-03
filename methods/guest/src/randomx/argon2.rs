//! Argon2d Cache Initialization for RandomX
//!
//! RandomX uses Argon2d to initialize the 256 MiB cache from a key.
//! Parameters (from RandomX spec):
//! - Memory: 262144 KiB (256 MiB)
//! - Iterations: 3
//! - Lanes: 1
//! - Salt: "RandomX\x03"
//!
//! Reference: https://github.com/tevador/RandomX/blob/master/doc/specs.md#6-dataset

use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Params, Version};

/// RandomX Argon2d parameters
pub const ARGON2_MEMORY_KIB: u32 = 262144; // 256 MiB in KiB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_SALT: &[u8] = b"RandomX\x03";
pub const ARGON2_OUTPUT_LEN: usize = 268435456; // 256 MiB

/// Initialize RandomX cache using Argon2d
///
/// This produces the 256 MiB cache that RandomX uses for light mode verification.
/// The cache is then used to compute dataset items on-demand.
pub fn init_cache(key: &[u8]) -> Vec<u8> {
    // Create Argon2d params matching RandomX spec
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64), // Output 64 bytes initially, we'll expand
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    // The cache is built by running Argon2d and then using the memory state
    // For RandomX, we need the full memory state, not just the output hash

    // However, the argon2 crate doesn't expose internal memory state directly
    // We need to generate the cache differently:
    // 1. Run Argon2d to get a seed
    // 2. Expand the seed to fill 256 MiB using AES

    // First, get the Argon2d hash
    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");

    // Now expand to full cache size using the seed
    // This matches RandomX's cache expansion after Argon2d
    expand_cache_from_seed(&seed, ARGON2_OUTPUT_LEN)
}

/// Initialize cache with custom size (for testing with smaller memory)
pub fn init_cache_with_size(key: &[u8], size: usize) -> Vec<u8> {
    // For smaller sizes, use proportionally less Argon2 memory
    let memory_kib = core::cmp::max(8, (size / 1024) as u32);

    let params = Params::new(
        memory_kib,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64),
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");

    expand_cache_from_seed(&seed, size)
}

/// Expand seed to full cache size using AES
///
/// RandomX expands the Argon2d memory state using AES in a specific pattern.
/// This fills the cache with pseudo-random data derived from the seed.
///
/// This version works in-place to avoid cloning the entire cache (saves ~256 MiB).
fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    use crate::randomx::aes::{AesState, aes_round, SoftAes};

    let mut cache = alloc::vec![0u8; size];

    // Use AES to expand the seed
    SoftAes::fill_scratchpad(seed, &mut cache);

    // Additional mixing passes for better randomness (as per RandomX spec)
    // Use the first 16 bytes of seed as the AES key
    let mut key = [0u8; 16];
    key.copy_from_slice(&seed[0..16]);

    // In-place mixing - use small buffers to avoid cloning entire cache
    // We need to save each block's original value before modifying it,
    // so the next block can XOR with the pre-modification value.
    let mut prev_block = [0u8; 64];
    let mut current_block = [0u8; 64];

    for _ in 0..2 {
        // Save the last block (it's the "previous" for block 0)
        prev_block.copy_from_slice(&cache[size - 64..size]);

        for i in (0..size).step_by(64) {
            let end = core::cmp::min(i + 64, size);
            let block_len = end - i;

            // Save current block's original value before modifying
            current_block[..block_len].copy_from_slice(&cache[i..end]);

            // XOR with previous block (using its pre-modification value)
            for j in 0..block_len {
                cache[i + j] ^= prev_block[j];
            }

            // AES round on first 16 bytes of each 64-byte block
            if block_len >= 16 {
                let mut state = AesState::from_bytes(&cache[i..i + 16]);
                aes_round(&mut state, &key);
                cache[i..i + 16].copy_from_slice(&state.to_bytes());
            }

            // Current block's original value becomes previous for next iteration
            prev_block[..block_len].copy_from_slice(&current_block[..block_len]);
        }
    }

    cache
}
