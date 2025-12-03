//! Shared code for RandomX zkVM guests
//!
//! This library provides the RandomX implementation shared by all phase guests.

#![no_std]

extern crate alloc;

pub mod randomx;

// ============================================================
// TEST CONFIGURATION - Adjust these values as needed
// ============================================================

/// Version string - UPDATE ALSO IN:
///   - Dockerfile.gpu-runtime (line ~74 and tag)
///   - deploy-akash-runtime.yaml (image tag)
///   - .github/workflows/docker-build-gpu-runtime.yml (tags)
pub const VERSION: &str = "v13";

/// Cache size for Phase 1 (Argon2d initialization)
/// Full Monero: 268435456 (256 MiB)
/// Current test: 134217728 (128 MiB)
pub const TEST_CACHE_SIZE: usize = 134217728; // 128 MiB

/// Scratchpad size for Phase 2 (VM execution)
/// Full Monero: 2097152 (2 MiB)
/// Current test: 1048576 (1 MiB)
pub const TEST_SCRATCHPAD_SIZE: usize = 1048576; // 1 MiB

/// Number of RandomX programs to execute
/// Full Monero: 8
/// Current test: 1
pub const TEST_PROGRAM_COUNT: usize = 1;

/// Iterations per program
/// Full Monero: 2048
/// Current test: 1024 (half)
pub const TEST_ITERATIONS: usize = 1024;

// ============================================================

// Re-export commonly used items
pub use randomx::aes::SoftAes;
pub use randomx::argon2::{init_cache, init_cache_with_size};
pub use randomx::blake2b::{blake2b_256, blake2b_hash};
pub use randomx::config::*;
pub use randomx::program::{Program, SuperscalarProgram};
pub use randomx::scratchpad::{Cache, Scratchpad};
pub use randomx::vm::VmState;
pub use randomx::{randomx_hash, randomx_hash_minimal, verify_difficulty};
