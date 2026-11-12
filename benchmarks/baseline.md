# Mosoo Performance Baseline & Modeled Gas Analysis

## Environment & Scope
- **Architecture**: x86_64 host CPU (empirical `mosoo-cli` timings) / `riscv32im-risc0-zkvm-elf` guest target (modeled cycle budget)
- **zkVM**: RISC Zero `1.0` (`risc0-zkvm = "1.0"` in `Cargo.toml`)
- **Cryptography Engine**: `blst` v0.3 (`min_pk`)

> **Important:** Native host nanosecond timings are measured directly by `cargo run -p mosoo-cli -- benchmarks` (`benchmarks/raw_crypto_benchmarks.json`). The zkVM cycle counts and comparative `zkcrypto/bls12_381` figures below are modeled reference estimates rather than local physical `cargo-risczero` prover measurements (see [`docs/BLS_LIBRARY_ANALYSIS.md`](../docs/BLS_LIBRARY_ANALYSIS.md)).

---

## 1. Modeled BLS12-381 Verification Cycle Breakdown

Reference cycle comparison between `blst` split pairing and pure-Rust `zkcrypto` baseline estimates:

| Operation | `blst` (RISC0 Accelerated) | `zkcrypto/bls12_381` | Speedup |
| :--- | :---: | :---: | :---: |
| `hash_to_G2(signing_root)` | ~4,200,000 cycles | ~12,100,000 cycles | **2.88x** |
| Miller Loop (2 pairings) | ~2,800,000 cycles | ~5,900,000 cycles | **2.11x** |
| Final Exponentiation ($\mathbb{F}_{p^{12}}$) | ~1,200,000 cycles | ~1,700,000 cycles | **1.42x** |
| **Total Computation** | **~8,200,000 cycles** | **~19,700,000 cycles** | **2.40x** |

---

## 2. 3-Transaction Gas Breakdown (LEZ Cap: 10M Gas)

| Transaction | Operation Description | Estimated Gas | Status |
| :--- | :--- | :---: | :---: |
| **Tx 1: `begin_update`** | Participation bit count, pubkey aggregation, `hash_to_G2` | ~5,400,000 | Pass (<10M) |
| **Tx 2: `miller_update`** | Dual Miller-loop pairing computation | ~4,200,000 | Pass (<10M) |
| **Tx 3: `finish_update`** | Final exponentiation, finality branch check, `HeaderRecord` write | ~3,800,000 | Pass (<10M) |
| **Total per Update** | Complete trustless consensus state advance | **~13,400,000** | **Split succeeds** |

---

## 3. Merkle-Patricia Trie Proof Verification

| Proof Type | State Proof Complexity | Compute Cycles | Proof Latency |
| :--- | :--- | :---: | :---: |
| **Account Balance** | 7-node trie path + RLP decode | ~2,100,000 cycles | ~45 ms |
| **Storage Slot** | Account trie path + Storage trie path | ~3,900,000 cycles | ~75 ms |
| **Predicate Evaluation** | In-memory comparison + deterministic SHA-256 ID | ~12,000 cycles | < 1 ms |
