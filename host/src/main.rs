//! Host program for Monero RandomX zkVM verification - Two Phase Architecture
//!
//! Phase 1: Cache initialization (Argon2d, 128 MiB) - Run once per ~2048 blocks
//! Phase 2: VM execution (scratchpad + programs) - Run for each block
//!
//! The cache proof can be reused for ~2-3 days worth of blocks!

use methods::{PHASE1_CACHE_ELF, PHASE1_CACHE_ID, PHASE2_VM_ELF, PHASE2_VM_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde::{Deserialize, Serialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

// Import argon2 for host-side cache computation
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

/// Version - keep in sync with methods/guest/src/lib.rs
const VERSION: &str = "v13";

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

/// Compute cache on host side (same algorithm as guest)
fn compute_cache_on_host(key: &[u8], size: usize) -> Vec<u8> {
    log("Initializing Argon2d parameters...");
    let memory_kib = std::cmp::max(8, (size / 1024) as u32);
    log(&format!("    Memory: {} KiB", memory_kib));
    log(&format!("    Iterations: {}", ARGON2_ITERATIONS));
    log(&format!("    Parallelism: {}", ARGON2_PARALLELISM));

    let params = Params::new(
        memory_kib,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64),
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    log("Running Argon2d hash...");
    let start = Instant::now();

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");

    log(&format!("Argon2d seed generated in {:.2?}", start.elapsed()));
    log("Expanding seed to full cache...");

    let expand_start = Instant::now();
    let cache = expand_cache_from_seed(&seed, size);
    log(&format!("Cache expanded in {:.2?}", expand_start.elapsed()));

    cache
}

/// Expand seed to cache (AES fill - must match guest implementation)
fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    let mut cache = vec![0u8; size];

    // AES fill matching guest's SoftAes::fill_scratchpad
    let mut state = [0u8; 64];
    state.copy_from_slice(seed);

    for chunk in cache.chunks_mut(64) {
        for i in 0..chunk.len() {
            chunk[i] = state[i % 64];
            state[i % 64] = state[i % 64].wrapping_add(1).wrapping_mul(0x9d);
        }
        for i in 0..64 {
            state[i] = state[i].wrapping_add(state[(i + 1) % 64]).rotate_left(3);
        }
    }

    cache
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
    // PHASE 1: Cache Initialization
    // =========================================================
    log_separator();
    println!("  PHASE 1: CACHE INITIALIZATION");
    log_separator();

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

    sys.refresh_memory();
    let mem_before_p1 = sys.used_memory();
    log(&format!("Memory before Phase 1: {:.2} GB used", mem_before_p1 as f64 / 1_073_741_824.0));

    log_separator();
    log("PHASE 1 PROVING STARTED");
    log("Computing Argon2d cache in zkVM...");
    log("This phase is REUSABLE for ~2048 blocks!");
    println!();

    let phase1_start = Instant::now();

    log("Calling prover.prove_with_ctx() for Phase 1...");
    log("(Progress updates from prover will appear below)");
    println!();

    let phase1_result = prover.prove_with_ctx(
        phase1_env,
        &VerifierContext::default(),
        PHASE1_CACHE_ELF,
        &opts,
    );

    let phase1_time = phase1_start.elapsed();

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

    let phase1_cycles = phase1_info.stats.total_cycles;

    log("Phase 1 Results:");
    println!("    Cache Hash: 0x{}", hex::encode(&phase1_output.cache_hash));
    println!("    Cache Size: {} MiB", phase1_output.cache_size / 1_048_576);
    println!("    Total Cycles: {}", format_number(phase1_cycles));
    println!("    Proving Time: {}", format_duration(phase1_time.as_secs()));
    println!("    Throughput: {:.0} cycles/sec", phase1_cycles as f64 / phase1_time.as_secs_f64());

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

    // =========================================================
    // Compute cache on host for Phase 2 input
    // =========================================================
    log_separator();
    println!("  PREPARING PHASE 2 INPUT");
    log_separator();

    log("Computing cache on host side...");
    log("(Must match what Phase 1 computed in zkVM)");
    println!();

    let cache_start = Instant::now();
    let cache = compute_cache_on_host(&randomx_key, phase1_output.cache_size);
    let cache_time = cache_start.elapsed();

    log(&format!("Host cache computation complete in {:.2?}", cache_time));
    log(&format!("Cache size: {} MiB ({} bytes)", cache.len() / 1_048_576, cache.len()));

    log("Computing cache hash for verification...");
    let host_cache_hash = blake2b_256(&cache);
    log(&format!("Host cache hash: 0x{}", hex::encode(&host_cache_hash)));

    // Verify host cache matches Phase 1's commitment
    log("Comparing with Phase 1 commitment...");
    if host_cache_hash != phase1_output.cache_hash {
        log("ERROR: Host cache hash doesn't match Phase 1 commitment!");
        log(&format!("    Phase 1: 0x{}", hex::encode(&phase1_output.cache_hash)));
        log(&format!("    Host:    0x{}", hex::encode(&host_cache_hash)));
        log("This indicates a bug in the cache computation!");
        return;
    }
    log("SUCCESS: Host cache hash matches Phase 1 commitment!");

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
    log(&format!("    Expected cache hash: 0x{}...", hex::encode(&phase1_output.cache_hash[..8])));

    let phase2_input = Phase2Input {
        cache,
        expected_cache_hash: phase1_output.cache_hash,
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
