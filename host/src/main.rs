//! Host program for Monero RandomX zkVM verification - Two Phase Architecture
//!
//! Phase 1: Cache initialization (Argon2d, 128 MiB) - Run once per ~2048 blocks
//! Phase 2: VM execution (scratchpad + programs) - Run for each block
//!
//! The cache proof can be reused for ~2-3 days worth of blocks!

use methods::{
    PHASE1_CACHE_ELF, PHASE1_CACHE_ID,
    PHASE1A_CACHE_SEGMENT_ELF, PHASE1A_CACHE_SEGMENT_ID,
    PHASE2_VM_ELF, PHASE2_VM_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

// Import argon2 for host-side cache computation
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

/// Version - keep in sync with methods/guest/src/lib.rs
const VERSION: &str = "v16";

/// Number of cache segments (keep in sync with guest)
const TEST_CACHE_SEGMENTS: usize = 32;

// ============================================================
// AES Implementation (must match guest exactly)
// ============================================================

/// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// GF(2^8) multiplication by 2
fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

/// AES state (4x4 bytes = 16 bytes)
#[derive(Clone, Copy)]
struct AesState {
    state: [u8; 16],
}

impl AesState {
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut state = [0u8; 16];
        state.copy_from_slice(&bytes[..16]);
        Self { state }
    }

    fn to_bytes(&self) -> [u8; 16] {
        self.state
    }

    fn sub_bytes(&mut self) {
        for byte in self.state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn shift_rows(&mut self) {
        let tmp = self.state[1];
        self.state[1] = self.state[5];
        self.state[5] = self.state[9];
        self.state[9] = self.state[13];
        self.state[13] = tmp;

        let tmp0 = self.state[2];
        let tmp1 = self.state[6];
        self.state[2] = self.state[10];
        self.state[6] = self.state[14];
        self.state[10] = tmp0;
        self.state[14] = tmp1;

        let tmp = self.state[15];
        self.state[15] = self.state[11];
        self.state[11] = self.state[7];
        self.state[7] = self.state[3];
        self.state[3] = tmp;
    }

    fn mix_columns(&mut self) {
        for col in 0..4 {
            let i = col * 4;
            let a = self.state[i];
            let b = self.state[i + 1];
            let c = self.state[i + 2];
            let d = self.state[i + 3];

            self.state[i] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
            self.state[i + 1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
            self.state[i + 2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
            self.state[i + 3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
        }
    }

    fn add_round_key(&mut self, key: &[u8; 16]) {
        for (s, k) in self.state.iter_mut().zip(key.iter()) {
            *s ^= *k;
        }
    }
}

fn aes_round(state: &mut AesState, key: &[u8; 16]) {
    state.sub_bytes();
    state.shift_rows();
    state.mix_columns();
    state.add_round_key(key);
}

/// Fill scratchpad using AES (matches guest's SoftAes::fill_scratchpad)
fn soft_aes_fill_scratchpad(seed: &[u8; 64], scratchpad: &mut [u8]) {
    let mut states = [
        AesState::from_bytes(&seed[0..16]),
        AesState::from_bytes(&seed[16..32]),
        AesState::from_bytes(&seed[32..48]),
        AesState::from_bytes(&seed[48..64]),
    ];

    let keys: [[u8; 16]; 4] = [
        [0xd7, 0x98, 0x3a, 0xad, 0x14, 0xab, 0x20, 0xdc, 0xa2, 0x9e, 0x6e, 0x02, 0x5f, 0x45, 0xb1, 0x1b],
        [0xbb, 0x04, 0x5d, 0x78, 0x45, 0x79, 0x98, 0x50, 0xd7, 0xdf, 0x28, 0xe5, 0x32, 0xe0, 0x48, 0xa7],
        [0xf1, 0x07, 0x59, 0xea, 0xc9, 0x72, 0x38, 0x2d, 0x67, 0x15, 0x88, 0x6c, 0x32, 0x59, 0x28, 0xab],
        [0x76, 0x9a, 0x49, 0xf0, 0x60, 0x14, 0xb6, 0x2c, 0xa9, 0x41, 0xc8, 0x19, 0x54, 0xb6, 0x75, 0xf7],
    ];

    let mut offset = 0;
    while offset < scratchpad.len() {
        for state in states.iter_mut() {
            for key in keys.iter() {
                aes_round(state, key);
            }
        }

        for state in states.iter() {
            let bytes = state.to_bytes();
            let end = std::cmp::min(offset + 16, scratchpad.len());
            let len = end - offset;
            scratchpad[offset..end].copy_from_slice(&bytes[..len]);
            offset += 16;
            if offset >= scratchpad.len() {
                break;
            }
        }
    }
}

// ============================================================

/// Phase 1 Input
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1Input {
    pub randomx_key: [u8; 32],
}

/// Phase 1 Output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1Output {
    pub cache_hash: [u8; 32],
    pub cache_size: usize,
    pub randomx_key: [u8; 32],
}

/// Phase 1a Input (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aInput {
    #[serde(with = "BigArray")]
    pub seed: [u8; 64],
    pub segment_index: usize,
    pub total_segments: usize,
    pub segment_start: usize,
    pub segment_size: usize,
    pub total_cache_size: usize,
    #[serde(with = "BigArray")]
    pub prev_block_pass1: [u8; 64],
    #[serde(with = "BigArray")]
    pub prev_block_pass2: [u8; 64],
}

/// Phase 1a Output (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aOutput {
    pub segment_hash: [u8; 32],
    pub segment_index: usize,
    pub total_segments: usize,
    pub segment_start: usize,
    pub segment_size: usize,
    pub seed_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub final_prev_block_pass1: [u8; 64],
    #[serde(with = "BigArray")]
    pub final_prev_block_pass2: [u8; 64],
}

/// Phase 2 Input
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Input {
    pub cache: Vec<u8>,
    pub expected_cache_hash: [u8; 32],
    pub randomx_key: [u8; 32],
    pub input_data: Vec<u8>,
    pub difficulty: u64,
}

/// Phase 2 Output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Output {
    pub pow_hash: [u8; 32],
    pub difficulty_valid: bool,
    pub cache_size: usize,
    pub scratchpad_size: usize,
}

/// Monero block header for PoW verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroBlockHeader {
    pub height: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_id: [u8; 32],
    pub nonce: u32,
    pub hashing_blob: Vec<u8>,
}

/// Argon2d parameters (must match guest)
const ARGON2_SALT: &[u8] = b"RandomX\x03";
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let hours = (now % 86400) / 3600;
    let minutes = (now % 3600) / 60;
    let seconds = now % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn log(msg: &str) {
    println!("[{}] {}", timestamp(), msg);
}

fn log_separator() {
    println!("\n{}", "=".repeat(60));
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{}h {}m {}s", hours, minutes, seconds)
}

/// Get test block data (Monero block 3,000,000)
fn get_test_block() -> MoneroBlockHeader {
    let mut hashing_blob = Vec::with_capacity(76);
    hashing_blob.push(14); // major version
    hashing_blob.push(14); // minor version
    hashing_blob.extend_from_slice(&[0x86, 0xda, 0x06]); // timestamp varint
    hashing_blob.extend_from_slice(&[0u8; 32]); // prev_id
    hashing_blob.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]); // nonce
    while hashing_blob.len() < 76 {
        hashing_blob.push(0);
    }

    MoneroBlockHeader {
        height: 3_000_000,
        major_version: 14,
        minor_version: 14,
        timestamp: 1700000000,
        prev_id: [0u8; 32],
        nonce: 0x12345678,
        hashing_blob,
    }
}

/// Get the RandomX key (normally derived from block at height - height % 2048)
fn get_randomx_key() -> [u8; 32] {
    [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ]
}

/// Compute Blake2b-256 hash
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Expand seed to cache (AES fill - must match guest implementation exactly)
fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    let mut cache = vec![0u8; size];

    // Use AES to expand the seed (matches guest's SoftAes::fill_scratchpad)
    soft_aes_fill_scratchpad(seed, &mut cache);

    // Additional mixing passes for better randomness (as per RandomX spec)
    // Use the first 16 bytes of seed as the AES key
    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    // In-place mixing - use small buffers to avoid cloning entire cache
    let mut prev_block = [0u8; 64];
    let mut current_block = [0u8; 64];

    for _ in 0..2 {
        // Save the last block (it's the "previous" for block 0)
        prev_block.copy_from_slice(&cache[size - 64..size]);

        for i in (0..size).step_by(64) {
            let end = std::cmp::min(i + 64, size);
            let block_len = end - i;

            // Save current block's original value before modifying
            current_block[..block_len].copy_from_slice(&cache[i..end]);

            // XOR with previous block (using its pre-modification value)
            for j in 0..block_len {
                cache[i + j] ^= prev_block[j];
            }

            // AES round on first 16 bytes of each 64-byte block (real AES)
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

/// Compute Argon2d seed only (for segmented proving)
fn compute_argon2_seed(key: &[u8], memory_kib: u32) -> [u8; 64] {
    let memory = std::cmp::max(8, memory_kib);

    let params = Params::new(
        memory,
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
    seed
}

/// Extract boundary states for segmented proving
/// Returns Vec of (prev_block_pass1, prev_block_pass2) for each segment
fn extract_segment_boundaries(
    seed: &[u8; 64],
    cache: &[u8],
    num_segments: usize,
) -> Vec<([u8; 64], [u8; 64])> {
    let size = cache.len();
    let segment_size = size / num_segments;

    // We need to track the prev_block state at each segment boundary
    // This requires simulating the mixing passes

    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    // First, get the initial AES fill (before mixing passes)
    let mut initial_fill = vec![0u8; size];
    soft_aes_fill_scratchpad(seed, &mut initial_fill);

    let mut boundaries = Vec::with_capacity(num_segments);

    // For segment 0, prev_block starts as the last 64 bytes of initial fill
    let mut prev_block_p1 = [0u8; 64];
    prev_block_p1.copy_from_slice(&initial_fill[size - 64..size]);

    // Simulate pass 1 to get boundaries
    let mut pass1_boundaries = vec![[0u8; 64]; num_segments];
    pass1_boundaries[0] = prev_block_p1;

    let mut current_block = [0u8; 64];
    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        // Save current block's original value
        current_block[..block_len].copy_from_slice(&initial_fill[i..end]);

        // Check if we're at a segment boundary (except segment 0)
        let segment_idx = i / segment_size;
        if i > 0 && i % segment_size == 0 && segment_idx < num_segments {
            pass1_boundaries[segment_idx] = prev_block_p1;
        }

        // Update prev_block (we track the ORIGINAL value, not XOR'd)
        prev_block_p1[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    // Now simulate pass 2 to get its boundaries
    // After pass 1, the cache is modified. We need the state after pass 1.
    // For pass 2, prev_block starts as the last 64 bytes AFTER pass 1
    let mut prev_block_p2 = [0u8; 64];
    prev_block_p2.copy_from_slice(&cache[size - 64..size]); // Use actual cache (after both passes)

    // Actually, we need the state after pass 1 only, not after pass 2
    // Let's compute pass 1 result first
    let mut after_pass1 = initial_fill.clone();
    let mut prev = [0u8; 64];
    prev.copy_from_slice(&after_pass1[size - 64..size]);
    let mut curr = [0u8; 64];

    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        curr[..block_len].copy_from_slice(&after_pass1[i..end]);

        for j in 0..block_len {
            after_pass1[i + j] ^= prev[j];
        }

        if block_len >= 16 {
            let mut state = AesState::from_bytes(&after_pass1[i..i + 16]);
            aes_round(&mut state, &key);
            after_pass1[i..i + 16].copy_from_slice(&state.to_bytes());
        }

        prev[..block_len].copy_from_slice(&curr[..block_len]);
    }

    // Now get pass 2 boundaries from after_pass1
    let mut pass2_boundaries = vec![[0u8; 64]; num_segments];
    prev_block_p2.copy_from_slice(&after_pass1[size - 64..size]);
    pass2_boundaries[0] = prev_block_p2;

    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        current_block[..block_len].copy_from_slice(&after_pass1[i..end]);

        let segment_idx = i / segment_size;
        if i > 0 && i % segment_size == 0 && segment_idx < num_segments {
            pass2_boundaries[segment_idx] = prev_block_p2;
        }

        prev_block_p2[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    // Combine boundaries
    for i in 0..num_segments {
        boundaries.push((pass1_boundaries[i], pass2_boundaries[i]));
    }

    boundaries
}

fn main() {
    log_separator();
    println!("  MONERO RANDOMX ZKVM - TWO PHASE VERIFICATION");
    println!("  Version: {} (Split Proofs)", VERSION);
    log_separator();

    println!();
    log("Architecture Overview:");
    println!("    Phase 1: Argon2d Cache Initialization");
    println!("        - Computes cache from RandomX key");
    println!("        - Outputs cache hash commitment");
    println!("        - REUSABLE for ~2048 blocks (~2-3 days)!");
    println!();
    println!("    Phase 2: VM Execution");
    println!("        - Receives cache as input");
    println!("        - Verifies cache hash matches Phase 1");
    println!("        - Fills scratchpad, runs VM programs");
    println!("        - Outputs final RandomX hash");
    println!();
    println!("    (Configuration values will be shown after proof generation)");

    // System information
    log_separator();
    let mut sys = System::new_all();
    sys.refresh_all();

    log("System Information:");
    println!("    CPU Cores: {}", sys.cpus().len());
    if let Some(cpu) = sys.cpus().first() {
        println!("    CPU Model: {}", cpu.brand());
    }
    println!(
        "    Total Memory: {:.2} GB",
        sys.total_memory() as f64 / 1_073_741_824.0
    );
    println!(
        "    Available Memory: {:.2} GB",
        sys.available_memory() as f64 / 1_073_741_824.0
    );

    // Check for GPU prover
    if let Ok(prover_env) = std::env::var("RISC0_PROVER") {
        log(&format!("Prover Backend: {}", prover_env));
    } else {
        log("Prover Backend: CPU (set RISC0_PROVER=cuda or metal for GPU)");
    }

    // Prepare test data
    let header = get_test_block();
    let randomx_key = get_randomx_key();
    let difficulty: u64 = 1;

    log_separator();
    log("Block Information:");
    println!("    Height: {}", header.height);
    println!("    Major Version: {} (RandomX era)", header.major_version);
    println!("    Hashing Blob: {} bytes", header.hashing_blob.len());
    println!("    RandomX Key: 0x{}...", hex::encode(&randomx_key[..8]));
    println!("    Difficulty: {} (test mode)", difficulty);

    let prover = default_prover();
    let opts = ProverOpts::default();
    let total_start = Instant::now();

    // =========================================================
    // PHASE 1: Cache Initialization (Segmented or Single)
    // =========================================================
    log_separator();
    if TEST_CACHE_SEGMENTS > 1 {
        println!("  PHASE 1: SEGMENTED CACHE PROVING ({} segments)", TEST_CACHE_SEGMENTS);
    } else {
        println!("  PHASE 1: CACHE INITIALIZATION");
    }
    log_separator();

    // First, compute cache on host (needed for both modes)
    let cache_size: usize = 134217728; // 128 MiB - keep in sync with guest
    let argon2_memory_kib = (cache_size / 1024) as u32;

    log("Computing Argon2d seed on host...");
    let seed_start = Instant::now();
    let seed = compute_argon2_seed(&randomx_key, argon2_memory_kib);
    log(&format!("Argon2d seed computed in {:.2?}", seed_start.elapsed()));
    log(&format!("Seed hash: 0x{}...", hex::encode(&blake2b_256(&seed)[..8])));

    log("Expanding seed to full cache on host...");
    let expand_start = Instant::now();
    let cache = expand_cache_from_seed(&seed, cache_size);
    log(&format!("Cache expanded in {:.2?}", expand_start.elapsed()));
    log(&format!("Cache size: {} MiB", cache.len() / 1_048_576));

    let cache_hash = blake2b_256(&cache);
    log(&format!("Cache hash: 0x{}", hex::encode(&cache_hash)));

    sys.refresh_memory();
    let mem_before_p1 = sys.used_memory();
    log(&format!("Memory before Phase 1: {:.2} GB used", mem_before_p1 as f64 / 1_073_741_824.0));

    let phase1_start = Instant::now();
    let mut phase1_cycles: u64 = 0;

    if TEST_CACHE_SEGMENTS > 1 {
        // =========================================================
        // SEGMENTED PROVING MODE
        // =========================================================
        log_separator();
        log(&format!("SEGMENTED CACHE PROVING: {} segments", TEST_CACHE_SEGMENTS));
        log("Argon2d runs on HOST (publicly verifiable)");
        log("zkVM proves AES expansion for each segment");
        println!();

        let segment_size = cache_size / TEST_CACHE_SEGMENTS;
        log(&format!("Segment size: {} MiB ({} bytes)", segment_size / 1_048_576, segment_size));

        // Extract boundary states for each segment
        log("Extracting segment boundary states...");
        let boundaries = extract_segment_boundaries(&seed, &cache, TEST_CACHE_SEGMENTS);
        log(&format!("Extracted {} boundary states", boundaries.len()));

        let mut segment_hashes: Vec<[u8; 32]> = Vec::new();

        for seg_idx in 0..TEST_CACHE_SEGMENTS {
            log_separator();
            log(&format!("SEGMENT {}/{}", seg_idx + 1, TEST_CACHE_SEGMENTS));

            let segment_start = seg_idx * segment_size;
            let (prev_p1, prev_p2) = &boundaries[seg_idx];

            let phase1a_input = Phase1aInput {
                seed,
                segment_index: seg_idx,
                total_segments: TEST_CACHE_SEGMENTS,
                segment_start,
                segment_size,
                total_cache_size: cache_size,
                prev_block_pass1: *prev_p1,
                prev_block_pass2: *prev_p2,
            };

            log(&format!("    Segment start: {} bytes", segment_start));
            log(&format!("    Segment size: {} bytes", segment_size));

            let seg_env = ExecutorEnv::builder()
                .write(&phase1a_input)
                .expect("Failed to write Phase 1a input")
                .build()
                .expect("Failed to build Phase 1a executor env");

            let seg_start = Instant::now();
            log("    Proving segment...");

            let seg_result = prover.prove_with_ctx(
                seg_env,
                &VerifierContext::default(),
                PHASE1A_CACHE_SEGMENT_ELF,
                &opts,
            );

            let seg_time = seg_start.elapsed();

            match seg_result {
                Ok(info) => {
                    let output: Phase1aOutput = info.receipt.journal.decode()
                        .expect("Failed to decode Phase 1a output");

                    phase1_cycles += info.stats.total_cycles;
                    segment_hashes.push(output.segment_hash);

                    log(&format!("    Segment {} PROVED in {}", seg_idx, format_duration(seg_time.as_secs())));
                    log(&format!("    Segment hash: 0x{}...", hex::encode(&output.segment_hash[..8])));
                    log(&format!("    Cycles: {}", format_number(info.stats.total_cycles)));

                    // Verify segment proof
                    match info.receipt.verify(PHASE1A_CACHE_SEGMENT_ID) {
                        Ok(_) => log("    Segment proof VALID!"),
                        Err(e) => {
                            log(&format!("ERROR: Segment {} verification failed: {}", seg_idx, e));
                            return;
                        }
                    }
                }
                Err(e) => {
                    log(&format!("ERROR: Segment {} failed: {}", seg_idx, e));
                    return;
                }
            }
        }

        // Verify segment hashes combine to full cache hash
        log_separator();
        log("Verifying segment hashes...");
        // For now, verify each segment matches the corresponding slice of the host cache
        for (seg_idx, seg_hash) in segment_hashes.iter().enumerate() {
            let seg_start = seg_idx * segment_size;
            let seg_end = seg_start + segment_size;
            let host_seg_hash = blake2b_256(&cache[seg_start..seg_end]);
            if *seg_hash != host_seg_hash {
                log(&format!("ERROR: Segment {} hash mismatch!", seg_idx));
                log(&format!("    Proof:  0x{}", hex::encode(seg_hash)));
                log(&format!("    Host:   0x{}", hex::encode(&host_seg_hash)));
                return;
            }
        }
        log("All segment hashes VERIFIED!");

    } else {
        // =========================================================
        // SINGLE PROOF MODE (original Phase 1)
        // =========================================================
        log("Preparing Phase 1 input...");
        let phase1_input = Phase1Input { randomx_key };
        log(&format!("    RandomX Key: 0x{}...", hex::encode(&randomx_key[..8])));

        log("Building Phase 1 executor environment...");
        let phase1_env = ExecutorEnv::builder()
            .write(&phase1_input)
            .expect("Failed to write Phase 1 input")
            .build()
            .expect("Failed to build Phase 1 executor env");
        log("Phase 1 executor environment ready");

        log_separator();
        log("PHASE 1 PROVING STARTED");
        log("Computing Argon2d cache in zkVM...");
        log("This phase is REUSABLE for ~2048 blocks!");
        println!();

        log("Calling prover.prove_with_ctx() for Phase 1...");
        log("(Progress updates from prover will appear below)");
        println!();

        let phase1_result = prover.prove_with_ctx(
            phase1_env,
            &VerifierContext::default(),
            PHASE1_CACHE_ELF,
            &opts,
        );

        let phase1_info = match phase1_result {
            Ok(info) => {
                println!();
                log("========================================");
                log("PHASE 1 PROVING COMPLETED SUCCESSFULLY!");
                log("========================================");
                info
            }
            Err(e) => {
                println!();
                log("========================================");
                log(&format!("ERROR: Phase 1 failed: {}", e));
                log("========================================");
                log("Possible causes:");
                println!("    - Out of memory");
                println!("    - Disk space exhausted");
                println!("    - zkVM execution error");
                return;
            }
        };

        let phase1_output: Phase1Output = phase1_info.receipt.journal.decode()
            .expect("Failed to decode Phase 1 output");

        phase1_cycles = phase1_info.stats.total_cycles;

        log("Phase 1 Results:");
        println!("    Cache Hash: 0x{}", hex::encode(&phase1_output.cache_hash));
        println!("    Cache Size: {} MiB", phase1_output.cache_size / 1_048_576);
        println!("    Total Cycles: {}", format_number(phase1_cycles));

        // Verify Phase 1 proof
        log("Verifying Phase 1 proof...");
        let verify1_start = Instant::now();
        match phase1_info.receipt.verify(PHASE1_CACHE_ID) {
            Ok(_) => {
                log(&format!("Phase 1 proof VALID! (verified in {:.2?})", verify1_start.elapsed()));
            }
            Err(e) => {
                log(&format!("ERROR: Phase 1 verification failed: {}", e));
                return;
            }
        }

        // Verify host cache matches Phase 1's commitment
        if cache_hash != phase1_output.cache_hash {
            log("ERROR: Host cache hash doesn't match Phase 1 commitment!");
            log(&format!("    Phase 1: 0x{}", hex::encode(&phase1_output.cache_hash)));
            log(&format!("    Host:    0x{}", hex::encode(&cache_hash)));
            log("This indicates a bug in the cache computation!");
            return;
        }
    }

    let phase1_time = phase1_start.elapsed();

    log_separator();
    log("Phase 1 Summary:");
    println!("    Mode: {}", if TEST_CACHE_SEGMENTS > 1 { format!("Segmented ({} segments)", TEST_CACHE_SEGMENTS) } else { "Single proof".to_string() });
    println!("    Cache Hash: 0x{}", hex::encode(&cache_hash));
    println!("    Cache Size: {} MiB", cache_size / 1_048_576);
    println!("    Total Cycles: {}", format_number(phase1_cycles));
    println!("    Proving Time: {}", format_duration(phase1_time.as_secs()));
    if phase1_time.as_secs() > 0 {
        println!("    Throughput: {:.0} cycles/sec", phase1_cycles as f64 / phase1_time.as_secs_f64());
    }

    // =========================================================
    // PHASE 2: VM Execution
    // =========================================================
    log_separator();
    println!("  PHASE 2: VM EXECUTION");
    log_separator();

    log("Preparing Phase 2 input...");
    let cache_size_mib = cache.len() / 1_048_576;
    log(&format!("    Cache size: {} MiB", cache_size_mib));
    log(&format!("    Input data: {} bytes", header.hashing_blob.len()));
    log(&format!("    Expected cache hash: 0x{}...", hex::encode(&cache_hash[..8])));

    let phase2_input = Phase2Input {
        cache,
        expected_cache_hash: cache_hash,
        randomx_key,
        input_data: header.hashing_blob.clone(),
        difficulty,
    };

    log("Building Phase 2 executor environment...");
    log(&format!("(This includes serializing {} MiB cache as input)", cache_size_mib));
    let env_start = Instant::now();
    let phase2_env = ExecutorEnv::builder()
        .write(&phase2_input)
        .expect("Failed to write Phase 2 input")
        .build()
        .expect("Failed to build Phase 2 executor env");
    log(&format!("Phase 2 executor environment ready in {:.2?}", env_start.elapsed()));

    sys.refresh_memory();
    let mem_before_p2 = sys.used_memory();
    log(&format!("Memory before Phase 2: {:.2} GB used", mem_before_p2 as f64 / 1_073_741_824.0));

    log_separator();
    log("PHASE 2 PROVING STARTED");
    log("Steps: Verify cache hash -> Fill scratchpad -> VM execution");
    println!();

    let phase2_start = Instant::now();

    log("Calling prover.prove_with_ctx() for Phase 2...");
    log("(Progress updates from prover will appear below)");
    println!();

    let phase2_result = prover.prove_with_ctx(
        phase2_env,
        &VerifierContext::default(),
        PHASE2_VM_ELF,
        &opts,
    );

    let phase2_time = phase2_start.elapsed();

    let phase2_info = match phase2_result {
        Ok(info) => {
            println!();
            log("========================================");
            log("PHASE 2 PROVING COMPLETED SUCCESSFULLY!");
            log("========================================");
            info
        }
        Err(e) => {
            println!();
            log("========================================");
            log(&format!("ERROR: Phase 2 failed: {}", e));
            log("========================================");
            log("Possible causes:");
            println!("    - Out of memory");
            println!("    - Disk space exhausted");
            println!("    - zkVM execution error");
            return;
        }
    };

    let phase2_output: Phase2Output = phase2_info.receipt.journal.decode()
        .expect("Failed to decode Phase 2 output");

    let phase2_cycles = phase2_info.stats.total_cycles;

    log("Phase 2 Results:");
    println!("    RandomX Hash: 0x{}", hex::encode(&phase2_output.pow_hash));
    println!("    Difficulty Valid: {}", phase2_output.difficulty_valid);
    println!("    Total Cycles: {}", format_number(phase2_cycles));
    println!("    Proving Time: {}", format_duration(phase2_time.as_secs()));
    println!("    Throughput: {:.0} cycles/sec", phase2_cycles as f64 / phase2_time.as_secs_f64());

    // Verify Phase 2 proof
    log("Verifying Phase 2 proof...");
    let verify2_start = Instant::now();
    match phase2_info.receipt.verify(PHASE2_VM_ID) {
        Ok(_) => {
            log(&format!("Phase 2 proof VALID! (verified in {:.2?})", verify2_start.elapsed()));
        }
        Err(e) => {
            log(&format!("ERROR: Phase 2 verification failed: {}", e));
            return;
        }
    }

    // =========================================================
    // FINAL RESULTS
    // =========================================================
    let total_time = total_start.elapsed();
    let total_cycles = phase1_cycles + phase2_cycles;

    log_separator();
    println!("  VERIFICATION COMPLETE!");
    log_separator();

    log("Final Results:");
    println!("    Block Height: {}", header.height);
    println!("    RandomX Hash: 0x{}", hex::encode(&phase2_output.pow_hash));
    println!("    Difficulty Valid: {}", phase2_output.difficulty_valid);

    log_separator();
    println!("  PERFORMANCE SUMMARY");
    log_separator();

    println!();
    println!("Phase 1 (Cache Init - REUSABLE for ~2048 blocks):");
    println!("    Cycles:      {}", format_number(phase1_cycles));
    println!("    Time:        {}", format_duration(phase1_time.as_secs()));
    println!("    Throughput:  {:.0} cycles/sec", phase1_cycles as f64 / phase1_time.as_secs_f64());

    println!();
    println!("Phase 2 (VM Execution - per block):");
    println!("    Cycles:      {}", format_number(phase2_cycles));
    println!("    Time:        {}", format_duration(phase2_time.as_secs()));
    println!("    Throughput:  {:.0} cycles/sec", phase2_cycles as f64 / phase2_time.as_secs_f64());

    println!();
    println!("Total:");
    println!("    Cycles:      {}", format_number(total_cycles));
    println!("    Time:        {}", format_duration(total_time.as_secs()));
    println!("    Throughput:  {:.0} cycles/sec", total_cycles as f64 / total_time.as_secs_f64());

    log_separator();
    println!("  PROOF SUMMARY");
    log_separator();

    println!();
    println!("Configuration (from proof outputs):");
    println!("    Cache Size:      {} MiB", phase2_output.cache_size / 1_048_576);
    println!("    Scratchpad Size: {} KiB", phase2_output.scratchpad_size / 1024);

    println!();
    println!("Proofs:");
    println!("    Phase 1: VALID (cache initialization)");
    println!("    Phase 2: VALID (VM execution)");

    println!();
    println!("Output:");
    println!("    Block Height:   {}", header.height);
    println!("    RandomX Hash:   0x{}", hex::encode(&phase2_output.pow_hash));
    println!("    Difficulty Met: {}", phase2_output.difficulty_valid);

    println!();
    log("IMPORTANT: Phase 1 proof can be cached and reused for ~2048 blocks!");
    log("           Only Phase 2 needs to run for each block verification.");

    log_separator();
}
