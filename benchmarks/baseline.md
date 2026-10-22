# Mosoo Performance Baseline & Gas Analysis

## Measurement Environment
- **Architecture**: x86_64 / RISC-V 32IM target
- **zkVM**: RISC Zero v1.2+
- **Cryptography Engine**: `blst` v0.3.17 (hardware accelerated)

---

## 1. BLS12-381 Verification Cycle Breakdown

Comparison between RISC0-accelerated `blst` and unaccelerated `zkcrypto`:

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
