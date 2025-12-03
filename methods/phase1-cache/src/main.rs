//! Phase 1: Cache Initialization
//!
//! This guest program handles Argon2d cache initialization.
//! Outputs the cache hash for verification by Phase 2.

#![no_main]
#![no_std]

extern crate alloc;

use guest::{blake2b_256, init_cache_with_size, TEST_CACHE_SIZE};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// Input to Phase 1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1Input {
    /// The RandomX key (seed hash)
    pub randomx_key: [u8; 32],
}

/// Output from Phase 1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1Output {
    /// Blake2b hash of the initialized cache
    pub cache_hash: [u8; 32],
    /// Cache size used
    pub cache_size: usize,
    /// The RandomX key (passed through for verification)
    pub randomx_key: [u8; 32],
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input from host
    let input: Phase1Input = env::read();

    // Initialize cache using Argon2d
    let cache = init_cache_with_size(&input.randomx_key, TEST_CACHE_SIZE);

    // Compute cache hash for verification in Phase 2
    let cache_hash = blake2b_256(&cache);

    // Commit output
    let output = Phase1Output {
        cache_hash,
        cache_size: TEST_CACHE_SIZE,
        randomx_key: input.randomx_key,
    };

    env::commit(&output);
}
