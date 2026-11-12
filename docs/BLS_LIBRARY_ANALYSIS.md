# BLS12-381 Library Analysis & Cryptographic Architecture

This document evaluates BLS12-381 verification libraries for Ethereum Altair/Electra/Fulu/Gloas sync-committee light clients inside the RISC Zero (`riscv32im-risc0-zkvm-elf`) zkVM on LEZ, explaining Mosoo's choice of **`blst`** and separating **locally measured host timings** from **modeled zkVM cycle estimates**.

---

## 1. Current Implementation (`blst` 0.3, `min_pk`)

Mosoo configures `blst = "0.3"` across `mosoo-core` (`Cargo.toml`) using Ethereum PoS's **`min_pk`** scheme:
- Validator public keys: **48-byte compressed G1** (`blst::min_pk::PublicKey`).
- Sync-committee aggregate signatures: **96-byte compressed G2** (`blst::min_pk::Signature`).
- Domain Separation Tag: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
- Quorum: strict participation bitfield check (`>= 342 / 512` validators) with key subgroup validation via `PublicKey::from_bytes` and G1 aggregation (`AggregatePublicKey::aggregate`).

### Why `blst`?
1. **Production Battle-Testing**: `blst` (Supranational) is the reference C/assembly BLS12-381 library used across production Ethereum consensus clients (Lighthouse, Prysm, Teku, Nimbus, Reth) and `a16z/helios`.
2. **Host + Portable RISC-V Compilation**: On x86_64/ARM64 hosts (`daemon`, `cli`, unit tests), `blst` uses optimized assembly. When targeting `riscv32im-risc0-zkvm-elf`, `blst`'s portable C backend compiles cleanly inside RISC Zero's `gcc`/RISC-V toolchain (using `cc` with deterministic flags in `docker/Dockerfile.guest`).
3. **Resumable 3-Transaction Split Pairing (`Begin -> Miller -> Finish`)**:
   - **Monolithic Bottleneck**: Executing `hash_to_G2` + dual Miller loops + final exponentiation + 512-key SSZ Merkleization + state updates in one transaction exceeds LEZ's single-transaction **10,000,000 gas cap**.
   - **Mosoo 3-Tx Pipeline** (`mosoo-core/src/crypto.rs`):
     1. `BeginUpdate`: bitfield & quorum check (`>= 342`), participating G1 key aggregation (`aggregate_participating_pubkeys`), and `blst_hash_to_g2`.
     2. `MillerUpdate`: `blst_two_miller_loops` evaluating $e(P_{\text{agg}}, H(m)) \cdot e(-G_1, \sigma)$ into intermediate $\mathbb{F}_{p^{12}}$ state serialized inside a digest-bound `JobAccount`.
     3. `FinishUpdate`: `blst_final_exp_and_verify` checking $\text{final\_exp}(M) \stackrel{?}{=} 1_{\mathbb{G}_T}$, followed by SSZ finality & committee handoff branch proofs.

---

## 2. Measurement vs Modeling Discipline

To maintain audit transparency, Mosoo strictly distinguishes:

| Category | Source in Repo | Status |
|---|---|---|
| **Host CPU timings (`blst` native x86_64)** | `cargo run -p mosoo-cli -- benchmarks` -> `benchmarks/raw_crypto_benchmarks.json` | **Measured empirically** on local CPU (`hash_to_g2`, `two_miller_loops`, `final_exp`, 512-key SSZ). |
| **Live LEZ v0.3.1 / `r0vm 3.0.5` ELF cycles (`mosoo_lc.bin`)** | `evidence/mosoo-testnet-v03/local_simulation.txt` + `lifecycle_manifest.json` | **Measured empirically in `r0vm 3.0.5`** (`Init=927,806`, `Begin=2,558,057`, `Miller=4,568,088`, `Finish=3,705,545` cycles — all `< 10M MAX_GAS_EXEC`) and executed live on `https://testnet.lez.logos.co` (`Co5EYuBR...`). |
| **3-Tx RISC Zero cycle & LEZ gas model (v0.4 baseline)** | `docs/BENCHMARKS.md`, `cli/src/main.rs` (`5.23M` / `2.82M` / `1.30M` cycles; `5.38M` / `4.18M` / `3.74M` gas) | **Modeled estimates** preserved as `v0.4` planning baseline; physical `mosoo-guest` STARK proof timing requires `SEGMENT_PO2=18` proving run. |
| **Pure-Rust library comparisons** (`zkcrypto/bls12_381`, `arkworks`, `substrate-bls12-381`) | Architectural comparison only | **Not compiled or benchmarked** inside Mosoo. Only qualitative architectural trade-offs are stated below. |

---

## 3. Alternative Libraries Considered (Qualitative Comparison)

| Criterion | `blst` (`min_pk`, Implemented) | `zkcrypto/bls12_381` (Pure Rust) | `ark-bls12-381` (Arkworks) |
|---|---|---|---|
| **Implementation Language** | C + Host Assembly | 100% Pure Rust (`no_std`) | 100% Pure Rust (`no_std`) |
| **RISC Zero Build Footprint** | Requires RISC-V C cross-compiler (`rzup install cpp` / `gcc`) | Pure Cargo (`rustc` only, zero C toolchain risk) | Pure Cargo + algebra traits |
| **Exposed Split-Pairing Primitives** | Direct `blst_miller_loop`, `blst_fp12_mul`, `blst_final_exp` (`blst::blst_fp12`) | Requires internal / `pairing` crate extension for arbitrary intermediate $\mathbb{F}_{p^{12}}$ checkpointing | Exposes `Bls12_381::multi_miller_loop` & `final_exponentiation` cleanly |
| **Ecosystem Alignment** | Matches `a16z/helios` and production CL nodes | Used cleanly in constrained `no_std` WASM / RISC-V guests (e.g., `sextant_lc` dual backend option) | Common inside Circom/Halo2/Arkworks SNARK verifiers |

### Key Takeaway & Future Hardening Option
Using `blst` gives Mosoo identical pairing & subgroup-check behavior to `helios` and native performance in `mosoo-daemon`, at the cost of requiring the C RISC-V toolchain (`rzup install cpp` in `docker/Dockerfile.guest`). Adding a Cargo feature flag for a pure-Rust `bls12_381` fallback remains a clean post-v0.4 hardening option if zero-C-dependency guest builds are desired.
