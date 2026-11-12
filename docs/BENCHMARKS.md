# Mosoo Performance Benchmarks & Gas Analysis

Measured RISC0 zkVM cycle counts (`r0vm 3.0.5`), host native CPU timings (`mosoo benchmarks`), modeled LEZ v0.4 gas budgets, and on-chain storage projections across a single `10,000,000` LEZ transaction gas ceiling.

---

## 1. Live `r0vm 3.0.5` Guest Measurements (`mosoo_lc`, LEZ v0.3.1)

Directly measured in `evidence/mosoo-testnet-v03/local_simulation.txt` running `artifacts/programs/v0.3/mosoo_lc.bin` (`ImageID: 961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0`) under LEZ's `10,000,000` `MAX_GAS_EXEC` cap:

| Stage / Instruction | Measured Guest Cycles (`r0vm 3.0.5`) | Input Bytes | 10M Gas Cap Margin |
| :--- | :---: | :---: | :---: |
| `Init` (slot `15632288`) | `927,806` | `26,124` | `90.7%` headroom |
| `Begin` (slot -> `15632352`) | `2,558,057` | `29,795` | `74.4%` headroom |
| `Miller` (dual Miller loops) | `4,568,088` | `355` | `54.3%` headroom |
| `Finish` (final exp + block `#26392691`) | `3,705,545` | `1,131` | `62.9%` headroom |
| `Attest` — WETH Balance | `229,129` | `4,320` | `97.7%` headroom |
| `Attest` — WETH Storage | `362,755` | `7,359` | `96.4%` headroom |
| `Attest` — USDC Receipt | `200,594` | `4,737` | `98.0%` headroom |
| `Attest` — Confidential Shielded | `212,812` | `4,769` | `97.9%` headroom |

Every live stage executes cleanly inside `10,000,000` cycles, confirming that a monolithic single-tx BLS verification exceeds the cap whereas the 3-transaction split preserves substantial safety margins on unmodified LEZ runtimes.

---

## 2. Modeled v0.4 Gas Budget & Host CPU Measurements

Running `cargo run -p mosoo-cli -- benchmarks` benchmarks host-native `blst` operations across 50 iterations (debug CLI build on Windows host) alongside Mosoo's `v0.4` modeled 3-tx cycle and PDA gas budget (`benchmarks/raw_crypto_benchmarks.json`):

| Pipeline Stage | `blst` Optimized Budget | Pure Software Baseline | Speedup | Host CPU (`50`-iter CLI) | Modeled LEZ Gas (Cycles + PDA) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Tx 1: `BeginUpdate`** | `5,232,000` cycles | `15,425,000` cycles | `2.95x` | `~192 µs` | `5,382,140` gas (`46.2%` headroom) |
| **Tx 2: `MillerUpdate`** | `2,822,000` cycles | `5,974,000` cycles | `2.12x` | `~666 µs` | `4,180,000` gas (`58.2%` headroom) |
| **Tx 3: `FinishUpdate`** | `1,298,000` cycles | `1,850,000` cycles | `1.42x` | `~432 µs` | `3,740,000` gas (`62.6%` headroom) |
| **3-Tx Pipeline Total** | **`9,352,000` cycles** | **`23,249,000` cycles** | **`2.49x`** | **`~1.29 ms`** | **`13,302,140` gas** |
| **SSZ 512-Pubkey Tree** | `184,200` cycles | `420,000` cycles | `2.28x` | `~13.44 ms` | Included in `Finish` / `Init` |

*(Host native timings vary slightly per run and reflect raw cryptographic primitives without STARK/SNARK proof generation; proving wall-clock time depends directly on prover CPU/GPU hardware.)*

---

## 3. Sync-Committee Amortized Gas Analysis

Each Ethereum sync committee serves for **256 epochs (8,192 slots / ~27.3 hours)**. Once the `13,302,140` modeled gas (or `10,831,690` live `r0vm 3.0.5` cycles across `Begin+Miller+Finish`) establishes a finalized `HeaderRecord`, unlimited state attestations and consumer claims anchor against it:

| Attestations per Period | Modeled Amortized Consensus / Claim | State Attestation (`AttestState`) | Consumer (`claim_atomic`) | Effective Total Gas / Claim |
| :---: | :---: | :---: | :---: | :---: |
| **1** (standalone) | `13,302,140` | `852,400` | `118,500` | `14,273,040` |
| **10** | `1,330,214` | `852,400` | `118,500` | `2,301,114` |
| **100** | `133,021` | `852,400` | `118,500` | `1,103,921` |
| **1,000** | `13,302` | `852,400` | `118,500` | `984,202` |
| **10,000** | `1,330` | `852,400` | `118,500` | `972,230` |

At moderate bridge throughput (~100 claims per sync period), consensus verification drops below ~12% of effective gas cost per claim; at high throughput (~1,000+ claims), it approaches ~1%.

---

## 4. On-Chain Storage Footprint & Pruning

| Account Type | PDA Seed | Size | Lifecycle |
| :--- | :--- | :---: | :--- |
| `InstanceAccount` | `["mosoo_instance", chain_id, instance_id]` | ~640 B | Persistent per network instance |
| `TrustedBridgeConfig` | `["mosoo_config"]` | ~1.2 KB | Persistent governance configuration |
| `JobAccount` | `["mosoo_job", instance_pda, nonce]` | ~2.4 KB | Temporary across 3-tx pipeline |
| `HeaderRecord` | `["mosoo_header", chain_id, slot]` | 256 B | Prunable past 54,000-slot weak-subjectivity window |
| `NullifierRecord` | `["mosoo_nullifier", nullifier_hash]` | 96 B | Permanent replay guard per claimed statement |

At 1 finality header per sync period (`~321/year`) and `10,000` claims/year, active storage grows by `~1.04 MB/year` (`~10.4 MB` over 10 years, or much smaller with historical `HeaderRecord` pruning). Even at 1 header per epoch (`~82,125/year`) and `100,000` claims/year, annual growth stays around `~30.6 MB/year`.

---

## 5. End-to-End Latency & Host Precompile Trade-off

- **Settlement Latency Driver:** Ethereum Casper FFG 2-epoch finalization (`64 slots` = **12.8 minutes typical / ~19.2 minutes worst case**) accounts for **>95%** of end-to-end bridging latency. Local relayer polling, `AttestState` verification, and LEZ block inclusion add well under 1 minute (`1-3` seconds LEZ confirmation plus local proof generation if STARK proving is enabled).
- **In-Program `blst` vs. Native Host Precompile (EIP-2537):** Moving pairing arithmetic to a native LEZ host precompile could drop BLS verification from ~9.35M–10.83M cycles across 3 transactions down to ~85k gas in 1 transaction, at the cost of requiring a core LEZ protocol fork. Keeping `blst` in-guest lets Mosoo deploy immediately on unmodified LEZ runtimes with zero additional host trust assumptions.

---

## Reproducing Measurements

```powershell
# Re-run host cryptographic workload benchmarks & regenerate benchmarks/raw_crypto_benchmarks.json
cargo run -p mosoo-cli -- benchmarks

# Inspect measured v0.3.1 r0vm 3.0.5 cycle trace
Get-Content evidence/mosoo-testnet-v03/local_simulation.txt
```
