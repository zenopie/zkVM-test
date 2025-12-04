# Monero RandomX zkVM Verification

**Version: v19** | Zero-knowledge proof system for Monero block verification

## Overview

This project enables trustless verification of Monero proof-of-work by generating ZK proofs of RandomX hash computation using RISC Zero zkVM. Designed for an optimistic bridge architecture:

- **Normal tier**: Bonded deposits with challenge period (no proof upfront)
- **Pro tier**: Full ZK proof for instant finality

## Architecture

### Two-Phase Proof System

```
Phase 1: Cache Initialization          Phase 2: Block PoW
(reusable ~2048 blocks)                (per block)
┌─────────────────────────┐            ┌─────────────────────────┐
│  64 segments × 4 MiB    │            │  8 programs × ~1.5 MiB  │
│  = 256 MiB total cache  │───────────▶│  with Merkle proofs     │
│                         │   Merkle   │                         │
│  Argon2d + AES expand   │    Root    │  RandomX VM execution   │
└─────────────────────────┘            └─────────────────────────┘
```

**Phase 1**: Proves correct cache generation from RandomX key
- 64 segments × 4 MiB = 256 MiB cache
- Argon2d seed → AES expansion
- Reusable for ~2048 blocks (~3 days)

**Phase 2**: Proves RandomX VM execution with Merkle proofs
- 8 program segments, each ~1.5 MiB input
- ~170× smaller than monolithic 256 MiB approach
- Pre-execution identifies accessed dataset items
- Merkle proofs verify items against Phase 1 root

### Merkle Tree Optimization

Instead of passing the full 256 MiB cache:

1. Build Merkle tree from ~4.2M dataset items (64 bytes each)
2. Pre-execute programs on host to identify ~2048 accessed items per program
3. Provide only accessed items with Merkle proofs (~1.5 MiB total)
4. zkVM verifies proofs and executes program

## Quick Start

### Prerequisites

```bash
# Install Risc0 toolchain
curl -L https://risczero.com/install | bash
rzup install
```

### Build & Run

```bash
# Test mode (uses dummy block data)
PROOF_MODE=block TEST_MODE=true cargo run -r -p host

# With GPU acceleration (recommended)
RISC0_PROVER=cuda PROOF_MODE=block cargo run -r -p host
```

### Docker (GPU Runtime)

```bash
# Build image
docker build -f Dockerfile.gpu-runtime -t randomx-zkvm-gpu .

# Run with GPU
docker run --gpus all randomx-zkvm-gpu
```

## Proof Modes

Set via `PROOF_MODE` environment variable:

| Mode | Description | Use Case |
|------|-------------|----------|
| `cache` | Prove all 64 cache segments | Pro tier deposit |
| `block` | Prove 8 program segments | Per-block verification |
| `challenge` | Prove single cache segment | Fraud proof |
| `full` | Both cache + block (default) | Complete verification |

## Configuration

### Environment Variables

```bash
# Proof mode
PROOF_MODE=block          # cache | block | challenge | full

# Input data source
TEST_MODE=true            # true = test data, false = real Monero data

# Real data mode (when TEST_MODE=false)
RANDOMX_KEY=<hex>         # 32-byte RandomX key
HASHING_BLOB=<hex>        # Block hashing blob
BLOCK_HEIGHT=3000000      # Block height (optional)
DIFFICULTY=1              # Target difficulty (optional)

# Challenge mode
CHALLENGE_SEGMENT=0       # Which segment (0-63)

# Prover backend
RISC0_PROVER=local        # local | cuda | metal
```

### Monero Specification

| Parameter | Value |
|-----------|-------|
| Cache Size | 256 MiB (64 × 4 MiB segments) |
| Scratchpad | 2 MiB |
| Programs | 8 × 2048 iterations |
| Dataset Items | ~4.2M (64 bytes each) |

## Project Structure

```
├── host/                        # Host-side prover
│   └── src/main.rs             # Merkle tree, pre-execution, proving
├── methods/
│   ├── guest/                  # Shared RandomX library
│   │   └── src/
│   │       ├── lib.rs          # Config & re-exports
│   │       └── randomx/
│   │           ├── aes.rs      # Software AES
│   │           ├── argon2.rs   # Cache initialization
│   │           ├── blake2b.rs  # Hashing
│   │           ├── merkle.rs   # Merkle tree proofs
│   │           ├── program.rs  # RandomX programs
│   │           ├── vm.rs       # VM execution
│   │           └── ...
│   ├── phase1a-cache-segment/  # Cache segment guest
│   ├── phase2-program/         # Program segment guest (v19)
│   └── phase2-vm/              # Legacy monolithic guest
├── Dockerfile.gpu-runtime
├── deploy-akash-runtime.yaml
└── env.example
```

## RandomX Implementation

### Components

| Component | Status |
|-----------|--------|
| Argon2d cache (256 MiB) | Complete |
| AES scratchpad fill | Complete |
| All 30 instructions | Complete |
| Program generation | Complete |
| Superscalar programs | Complete |
| Light mode dataset | Complete |
| Difficulty verification | Complete |
| Merkle proofs | Complete (v19) |

### All 30 RandomX Instructions

**Integer**: `IADD_RS`, `IADD_M`, `ISUB_R`, `ISUB_M`, `IMUL_R`, `IMUL_M`, `IMULH_R`, `IMULH_M`, `ISMULH_R`, `ISMULH_M`, `IMUL_RCP`, `INEG_R`, `IXOR_R`, `IXOR_M`, `IROR_R`, `IROL_R`, `ISWAP_R`

**Floating Point**: `FSWAP_R`, `FADD_R`, `FADD_M`, `FSUB_R`, `FSUB_M`, `FSCAL_R`, `FMUL_R`, `FDIV_M`, `FSQRT_R`

**Control**: `CBRANCH`, `CFROUND`, `ISTORE`, `NOP`

## Performance

### GPU Acceleration (Required for Practical Use)

| GPU | Relative Speed |
|-----|----------------|
| CPU | 1× baseline |
| Metal (M1/M2) | 10-30× |
| CUDA (RTX 4090) | 80-100× |
| CUDA (H100) | 150-200× |

### Estimated Times (H100)

| Phase | Segments | Est. Time |
|-------|----------|-----------|
| Phase 1 (cache) | 64 | 4-8 hours |
| Phase 2 (block) | 8 | 1-2 hours |
| Challenge | 1 | 10-20 min |

Phase 1 cache proof reusable for ~2048 blocks (~3 days).

## Security Model

1. **Cache Commitment**: Phase 1 proves correct cache from RandomX key
2. **Merkle Binding**: Program segments verify items against committed root
3. **Chained Execution**: Program outputs chain to next program inputs
4. **Final Hash**: Last program outputs verified PoW hash

## Deployment

### Akash (Decentralized GPU Cloud)

```bash
# Deploy with SDL
akash tx deployment create deploy-akash-runtime.yaml
```

### Other GPU Clouds

```bash
# Build and push
docker build -f Dockerfile.gpu-runtime -t ghcr.io/USER/randomx-zkvm:gpu-runtime-v19 .
docker push ghcr.io/USER/randomx-zkvm:gpu-runtime-v19

# Run on Vast.ai, RunPod, Lambda, etc.
docker run --gpus all ghcr.io/USER/randomx-zkvm:gpu-runtime-v19
```

## References

- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [RISC Zero Documentation](https://dev.risczero.com/)
- [Monero Research Lab](https://www.getmonero.org/resources/research-lab/)

## License

MIT
