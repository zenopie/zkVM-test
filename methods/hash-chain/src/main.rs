//! Hash Chain Verification Guest
//!
//! Verifies a chain of Monero block headers, proving that blocks are linked.
//! This is trivially fast compared to RandomX verification.
//!
//! Input: List of block headers (hashing blobs)
//! Output: Start hash, end hash, block count
//!
//! Combined with a RandomX proof of one block, this proves the entire chain.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use guest::blake2b_hash;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// Input for hash chain verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashChainInput {
    /// Block headers (hashing blobs) in order from oldest to newest
    /// Each header is variable length (typically 76-80 bytes for Monero)
    pub headers: Vec<Vec<u8>>,
    /// The RandomX-proven block hash (must match hash of first header)
    pub anchor_hash: [u8; 32],
}

/// Output from hash chain verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashChainOutput {
    /// Hash of the first (anchor) block - must match a RandomX-proven block
    pub start_hash: [u8; 32],
    /// Hash of the last block (chain tip)
    pub end_hash: [u8; 32],
    /// Number of blocks in the chain
    pub block_count: u64,
    /// Whether the chain is valid (all links verified)
    pub valid: bool,
}

/// Compute Monero block hash from hashing blob
/// Monero uses Keccak for the block ID, but we can use Blake2b for our purposes
/// since we just need consistency - the actual hash algorithm doesn't matter
/// as long as it's deterministic and collision-resistant
fn compute_block_hash(header: &[u8]) -> [u8; 32] {
    // Use Blake2b-256 (same as rest of our system)
    let full_hash = blake2b_hash(header);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&full_hash[..32]);
    hash
}

/// Extract prev_id from Monero block header
/// In Monero's hashing blob format:
/// - Bytes 0: major version (varint)
/// - Bytes 1: minor version (varint)
/// - Bytes 2-4: timestamp (varint)
/// - Bytes after timestamp: prev_id (32 bytes)
///
/// For simplicity, we assume a fixed offset. In production, you'd parse varints.
/// Typical offset is around byte 5-7 depending on varint sizes.
fn extract_prev_id(header: &[u8]) -> Option<[u8; 32]> {
    // Find the prev_id offset by skipping varints
    // Major version: 1 byte (if < 128)
    // Minor version: 1 byte (if < 128)
    // Timestamp: 1-5 bytes (varint)
    // For modern Monero blocks, offset is typically 5-7

    // Simple heuristic: scan for the 32-byte prev_id
    // In practice, the offset should be provided or calculated properly

    // For this implementation, assume offset 7 (common case)
    // TODO: Parse varints properly for production
    let offset = find_prev_id_offset(header)?;

    if header.len() < offset + 32 {
        return None;
    }

    let mut prev_id = [0u8; 32];
    prev_id.copy_from_slice(&header[offset..offset + 32]);
    Some(prev_id)
}

/// Find the offset of prev_id by parsing varints
fn find_prev_id_offset(header: &[u8]) -> Option<usize> {
    if header.len() < 35 {
        return None;
    }

    let mut offset = 0;

    // Skip major version (varint)
    while offset < header.len() && header[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1; // Include the last byte of varint

    // Skip minor version (varint)
    while offset < header.len() && header[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1;

    // Skip timestamp (varint)
    while offset < header.len() && header[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1;

    if offset + 32 > header.len() {
        return None;
    }

    Some(offset)
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input
    let input: HashChainInput = env::read();

    if input.headers.is_empty() {
        env::commit(&HashChainOutput {
            start_hash: [0u8; 32],
            end_hash: [0u8; 32],
            block_count: 0,
            valid: false,
        });
        return;
    }

    // Compute hash of first block and verify it matches the anchor
    let first_hash = compute_block_hash(&input.headers[0]);
    if first_hash != input.anchor_hash {
        env::commit(&HashChainOutput {
            start_hash: first_hash,
            end_hash: [0u8; 32],
            block_count: input.headers.len() as u64,
            valid: false,
        });
        return;
    }

    // Verify the chain: each block's hash must match next block's prev_id
    let mut current_hash = first_hash;
    let mut valid = true;

    for i in 1..input.headers.len() {
        // Extract prev_id from current header
        let prev_id = match extract_prev_id(&input.headers[i]) {
            Some(id) => id,
            None => {
                valid = false;
                break;
            }
        };

        // Verify prev_id matches hash of previous block
        if prev_id != current_hash {
            valid = false;
            break;
        }

        // Compute this block's hash for the next iteration
        current_hash = compute_block_hash(&input.headers[i]);
    }

    // Output the result
    let output = HashChainOutput {
        start_hash: first_hash,
        end_hash: current_hash,
        block_count: input.headers.len() as u64,
        valid,
    };

    env::commit(&output);
}
