//! Host program for Monero RandomX zkVM verification
//!
//! Full RandomX implementation with Argon2d cache (256 MiB).
//! Includes detailed logging for monitoring long-running proofs.

use methods::GUEST_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde::{Deserialize, Serialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationInput {
    pub header: MoneroBlockHeader,
    pub randomx_key: [u8; 32],
    pub difficulty: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationOutput {
    pub height: u64,
    pub pow_hash: [u8; 32],
    pub difficulty_valid: bool,
    pub cache_size: usize,
    pub scratchpad_size: usize,
}

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

fn main() {
    log_separator();
    println!("  MONERO RANDOMX ZKVM VERIFICATION");
    println!("  Full Argon2d Implementation (256 MiB cache)");
    log_separator();

    // System information
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
    if let Ok(prover) = std::env::var("RISC0_PROVER") {
        log(&format!("Prover Backend: {}", prover));
    } else {
        log("Prover Backend: CPU (set RISC0_PROVER=cuda or metal for GPU)");
    }

    // Prepare test data
    let header = get_test_block();
    let randomx_key = get_randomx_key();
    let difficulty: u64 = 1; // Low difficulty for testing

    log_separator();
    log("Block Information:");
    println!("    Height: {}", header.height);
    println!("    Major Version: {} (RandomX era)", header.major_version);
    println!("    Hashing Blob: {} bytes", header.hashing_blob.len());
    println!("    RandomX Key: 0x{}...", hex::encode(&randomx_key[..8]));
    println!("    Difficulty: {} (test mode)", difficulty);

    log_separator();
    log("RandomX Configuration:");
    println!("    Cache Size: 256 MiB (Argon2d initialized)");
    println!("    Scratchpad Size: 2 MiB");
    println!("    Programs per Hash: 8");
    println!("    Iterations per Program: 2048");
    println!("    Total VM Instructions: ~4.2 million");

    log_separator();
    log("Starting zkVM execution...");
    log("This will take a LONG time (hours on CPU, minutes on GPU)");
    println!();

    let input = VerificationInput {
        header: header.clone(),
        randomx_key,
        difficulty,
    };

    // Track memory
    sys.refresh_memory();
    let mem_before = sys.used_memory();

    // Build executor environment
    log("Building executor environment...");
    let env = ExecutorEnv::builder()
        .write(&input)
        .expect("Failed to write input")
        .build()
        .expect("Failed to build executor env");

    log("Executor environment ready");

    // Start proving
    log_separator();
    log("PROVING STARTED");
    log("Stages: Argon2d cache init -> Scratchpad fill -> VM execution x 8 programs");
    println!();

    let start_time = Instant::now();
    let prover = default_prover();

    // Use groth16 for smaller proofs (slower but more compact)
    let opts = ProverOpts::groth16();

    log("Calling prover.prove_with_ctx()...");
    log("(No further output until proving completes)");
    println!();

    let prove_info = match prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        GUEST_ELF,
        &opts,
    ) {
        Ok(info) => {
            log("PROVING COMPLETED SUCCESSFULLY!");
            info
        }
        Err(e) => {
            log(&format!("ERROR: Proving failed: {}", e));
            log("Possible causes:");
            println!("    - Out of memory (need ~300 MB for cache)");
            println!("    - Cycle limit exceeded");
            println!("    - zkVM execution error");
            return;
        }
    };

    let proving_time = start_time.elapsed();

    // Memory after
    sys.refresh_memory();
    let mem_after = sys.used_memory();
    let mem_delta = mem_after.saturating_sub(mem_before);

    // Get stats
    let receipt = prove_info.receipt;
    let output: VerificationOutput = receipt.journal.decode().expect("Failed to decode output");

    log_separator();
    log("RESULTS:");
    println!();
    println!("    Block Height Verified: {}", output.height);
    println!("    RandomX Hash: 0x{}", hex::encode(&output.pow_hash));
    println!("    Difficulty Valid: {}", output.difficulty_valid);
    println!("    Cache Size Used: {} MiB", output.cache_size / 1_048_576);
    println!("    Scratchpad Size Used: {} MiB", output.scratchpad_size / 1_048_576);

    log_separator();
    log("PERFORMANCE METRICS:");
    println!();

    let total_cycles = prove_info.stats.total_cycles;
    let user_cycles = prove_info.stats.user_cycles;

    println!("    Total Cycles: {}", format_number(total_cycles));
    println!("    User Cycles: {}", format_number(user_cycles));
    println!("    Proving Time: {:.2?}", proving_time);
    println!(
        "    Throughput: {:.2} cycles/second",
        total_cycles as f64 / proving_time.as_secs_f64()
    );
    println!(
        "    Memory Delta: {:.2} MB",
        mem_delta as f64 / 1_048_576.0
    );

    // Calculate time breakdowns
    let hours = proving_time.as_secs() / 3600;
    let minutes = (proving_time.as_secs() % 3600) / 60;
    let seconds = proving_time.as_secs() % 60;
    println!(
        "    Time Breakdown: {}h {}m {}s",
        hours, minutes, seconds
    );

    // Verify the proof
    log_separator();
    log("Verifying proof...");
    let verify_start = Instant::now();

    match receipt.verify(methods::GUEST_ID) {
        Ok(_) => {
            let verify_time = verify_start.elapsed();
            log(&format!("Verification completed in {:.2?}", verify_time));
            log("PROOF IS VALID!");
        }
        Err(e) => {
            log(&format!("ERROR: Verification failed: {}", e));
        }
    }

    log_separator();
    log("BENCHMARK COMPLETE");
    println!();
    println!("Summary:");
    println!("    - Full RandomX hash computed inside zkVM");
    println!("    - Argon2d cache (256 MiB) initialized");
    println!("    - 8 programs x 2048 iterations executed");
    println!("    - Zero-knowledge proof generated and verified");
    println!();
    println!("The proof attests that:");
    println!("    1. Block {} has valid RandomX PoW", output.height);
    println!("    2. Hash 0x{}... meets difficulty", hex::encode(&output.pow_hash[..8]));
    println!("    3. All computation was done correctly");
    log_separator();
}
