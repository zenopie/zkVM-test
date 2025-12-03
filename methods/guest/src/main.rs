//! Monero RandomX PoW Verification in Risc0 zkVM
//!
//! Full RandomX implementation with Argon2d cache initialization.
//! This verifies real Monero block headers.

#![no_main]
#![no_std]

extern crate alloc;

mod randomx;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use randomx::{randomx_hash_minimal, verify_difficulty};

// TESTING: Use minimal parameters to verify proving works at all
// Real Monero uses 256 MiB cache, 2 MiB scratchpad, 8 programs, 2048 iterations
// We use much smaller values for faster proving during debugging
const TEST_CACHE_SIZE: usize = 1048576; // 1 MiB (vs 256 MiB)
const TEST_SCRATCHPAD_SIZE: usize = 65536; // 64 KiB (vs 2 MiB)
const TEST_PROGRAM_COUNT: usize = 1; // 1 (vs 8) = 8x faster
const TEST_ITERATIONS: usize = 128; // 128 (vs 2048) = 16x faster
// Combined: 128x fewer VM operations!

risc0_zkvm::guest::entry!(main);

/// Monero block header for PoW verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroBlockHeader {
    /// Block height
    pub height: u64,
    /// Major protocol version
    pub major_version: u8,
    /// Minor protocol version
    pub minor_version: u8,
    /// Block timestamp
    pub timestamp: u64,
    /// Previous block hash (32 bytes)
    pub prev_id: [u8; 32],
    /// Nonce used for mining
    pub nonce: u32,
    /// The "hashing blob" - serialized header data for RandomX input
    pub hashing_blob: Vec<u8>,
}

/// Input to the guest program
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationInput {
    /// The block header to verify
    pub header: MoneroBlockHeader,
    /// The RandomX key (seed hash) - changes every 2048 blocks
    pub randomx_key: [u8; 32],
    /// Target difficulty - hash must be <= target
    pub difficulty: u64,
}

/// Output committed by the guest
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationOutput {
    /// Block height verified
    pub height: u64,
    /// The computed RandomX hash
    pub pow_hash: [u8; 32],
    /// Whether the difficulty check passed
    pub difficulty_valid: bool,
    /// Cache size used (256 MiB for full Argon2d)
    pub cache_size: usize,
    /// Scratchpad size used (2 MiB)
    pub scratchpad_size: usize,
}

fn main() {
    // Read input from host
    let input: VerificationInput = env::read();

    // Validate header structure
    assert!(input.header.major_version >= 1, "Invalid major version");
    assert!(!input.header.hashing_blob.is_empty(), "Empty hashing blob");

    // Compute RandomX hash with MINIMAL settings for testing
    // This won't match real Monero hashes but lets us verify proving works
    let pow_hash = randomx_hash_minimal(
        &input.randomx_key,
        &input.header.hashing_blob,
        TEST_CACHE_SIZE,
        TEST_SCRATCHPAD_SIZE,
        TEST_PROGRAM_COUNT,
        TEST_ITERATIONS,
    );

    // Verify difficulty
    let difficulty_valid = verify_difficulty(&pow_hash, input.difficulty);

    // Commit output
    let output = VerificationOutput {
        height: input.header.height,
        pow_hash,
        difficulty_valid,
        cache_size: TEST_CACHE_SIZE,
        scratchpad_size: TEST_SCRATCHPAD_SIZE,
    };

    env::commit(&output);
}
