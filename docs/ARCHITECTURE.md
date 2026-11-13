# Mosoo Protocol Architecture Specification

Technical architecture, data structures, runtime execution model, and cryptographic verification pipelines for the **Mosoo Ethereum Consensus & State Attestation Module** on the Logos Execution Zone (LEZ).

---

## 1. Executive System Overview

Mosoo is a trustless, modular state attestation protocol designed natively for the Logos Execution Zone. It enables LEZ smart contracts to trustlessly verify any past or present fact from Ethereum consensus and execution layers—including account balances, contract storage slots, and EIP-2718 typed transaction receipt event logs.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Mosoo Architecture Flow                           │
│                                                                             │
│   [ Ethereum Consensus (Beacon Chain) ]                                     │
│                  │                                                          │
│                  ▼  Finalized Headers & Sync Committee Signatures           │
│   [ mosoo-daemon (Autonomous Relayer) ]                                     │
│                  │  - Randomized submission deferral (jitter)               │
│                  │  - Logos Ethereum Core verified proxy routing            │
│                  ▼                                                          │
│   [ Logos Execution Zone (LEZ) - In-Guest zkVM Verifier ]                   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 3-Transaction Split BLS Verification Pipeline                       │   │
│   │   1. BeginUpdate  ──► 2. MillerUpdate ──► 3. FinishUpdate           │   │
│   │   (see BENCHMARKS.md & local_simulation.txt for cycle measurements) │   │
│   │                                                                     │   │
│   │ Authenticated Light-Client State (PDA: ["mosoo_instance", id])      │   │
│   │   ├── Current & Next Sync Committee Public Key Commitments          │   │
│   │   └── Finalized Header Records (slot, state_root, receipts_root)    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                  │                                                          │
│                  ▼ Cross-Program Invocation (CPI) - Atomic Same-Tx          │
│   [ Consumer Smart Contracts (e.g., erc20-receiver, ether-receiver) ]       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. State / Receipt Proof Verification via MPT (alloy-trie)          │   │
│   │ 2. Dynamic Predicate Evaluation (Equal, AtLeast, LessThan, etc.)    │   │
│   │ 3. Canonical V2 Statement ID Derivation & Nullifier Enforcement     │   │
│   │ 4. Authorized Consumer Action (Token Minting, Ledger Crediting)     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Modular Repository Layout

The Mosoo codebase is structured into isolated, independently testable crates:

```text
lez-mosoo/
├── methods/guest/             # RISC Zero zkVM guest program target
│   └── src/main.rs            # In-guest dispatch (Begin/Miller/Finish/AttestState) & shielded journals
├── mosoo-core/                # Pure-Rust core cryptographic types & verification logic
│   ├── src/crypto.rs          # BLS12-381 `blst` split pairing, SSZ hash-tree-root, fork gindices
│   ├── src/verifier.rs        # Light client state transitions, committee rotation, LezRuntimeAdapter
│   ├── src/inclusion.rs       # Merkle-Patricia Trie (`alloy-trie`) & EIP-2718 receipt-log verifier
│   ├── src/predicate.rs       # Dynamic predicate evaluation engine & V2 Statement ID derivation
│   ├── src/spel.rs            # SPEL program account/PDA schema helpers
│   ├── src/types.rs           # Account schemas, HeaderRecord, InstanceAccount, TrustedBridgeConfig
│   ├── src/error.rs           # Typed MosooError hierarchy (plus src/outbound_zk.rs for ABI & burn witness)
│   └── tests/                 # 9 integration & adversarial test suites (174 tests)
│       ├── lez_v04_acceptance_tests.rs  # 4 offline LEZ v0.4-target conformance tests
│       ├── adversarial_mutation_tests/  # 50 tests across 4 submodules
│       ├── security_hardening_tests/    # 58 regression tests across 4 submodules
│       ├── real_chain_vectors_tests.rs  # 4 tests on real Mainnet Fulu, Sepolia Gloas & Hoodi Fulu vectors
│       └── ...                          # bridge (25), lc (22), privacy (6), seq (4), e2e (2)
├── daemon/                    # Autonomous consensus update daemon (`mosoo-daemon`)
│   └── src/                   # main.rs (polling, jitter 1.0x–2.5x, proxy routing) + tests.rs (18 tests)
├── cli/                       # Developer command-line interface (`mosoo-cli`)
│   └── src/                   # main.rs, demo.rs, attest.rs, consensus.rs + tests.rs (7 tests)
├── consumers/                 # Reference consumer implementations
│   ├── erc20-receiver/src/    # lib.rs + tests.rs (event-log proof consumer, shielded claims, nullifiers)
│   └── ether-receiver/src/    # lib.rs + tests.rs (account balance / ETH deposit consumer, mETH ledger)
├── contracts/                 # Ethereum escrow & settlement contracts
│   ├── MosooLocker.sol        # EIP-170 hardened v4 live on Sepolia (0xF94eA0F9...); source adds ZK unlock (24,375 B)
│   ├── MosooZkBurnVerifier.sol# Modular RISC Zero IRiscZeroVerifier outbound burn & root verifier (6,199 B)
│   └── test/                  # 31/31 Foundry tests (MosooLocker.t.sol 27 + MosooZkBurnVerifier.t.sol 4)
├── vectors/                   # Live Ethereum Beacon Chain JSON fixtures (Sepolia Gloas, Hoodi Fulu)
└── docs/                      # Architectural, deployment, migration, and security documentation
```

---

## 3. In-Guest zkVM Cryptographic Pipeline

### 3.1 3-Transaction Split BLS Pipeline
A single-shot 512-validator sync-committee pairing check exceeds LEZ's `10,000,000` single-transaction gas limit (~`13.30M` modeled total gas, or `~9.35M` modeled base prover cycles across stages before gas metering; live `r0vm 3.0.5` cycles measured for `mosoo_lc` in `evidence/mosoo-testnet-v03/local_simulation.txt` are `Begin = 2,558,057`, `Miller = 4,568,088`, `Finish = 3,705,545`).

Mosoo splits the cryptographic verification into three sequential transactions anchored by a `JobAccount` PDA:

1. **`BeginUpdate` (Stage 1):**
   - Ingests the update header, slot, and committee participation bitfield.
   - Verifies participation threshold ($\ge 342 / 512$ validators, or $66.8\%$).
   - Decompresses and validates 512-bit BLS12-381 public keys for participating validators.
   - In-Guest Cycles: **5,232,000** | Harness Gas: **5,382,140** (46.2% headroom vs 10M limit).
2. **`MillerUpdate` (Stage 2):**
   - Executes multi-Miller loop computation over the aggregated G1 public key and G2 signature.
   - Evaluates intermediate pairing accumulators without final exponentiation.
   - In-Guest Cycles: **2,822,000** | Harness Gas: **4,180,000** (58.2% headroom vs 10M limit).
3. **`FinishUpdate` (Stage 3):**
   - Completes the final exponentiation in $\mathbb{F}_{p^{12}}$ and checks equality to the identity element.
   - Traverses SSZ generalized index trees to authenticate `next_sync_committee_branch` (if rotation epoch).
   - Commits canonical `HeaderRecord` to the light client instance PDA and destroys the temporary `JobAccount`.
   - In-Guest Cycles: **1,298,000** | Harness Gas: **3,740,000** (62.6% headroom vs 10M limit).

Total split cycles: **9,352,000 cycles** across 3 transactions, ensuring every transaction operates with substantial safety margins.

### 3.2 Fork-Aware SSZ Generalized Index Proof Trees
Ethereum consensus container layouts shift across hard forks. Mosoo implements dynamic generalized index calculation:
- **Altair & Bellatrix:** 16-leaf beacon state tree.
- **Capella & Deneb:** 32-leaf execution payload tree (`generalized_index = 25`).
- **Electra, Fulu & Gloas:** Dynamic payload index mapping with simulated ePBS execution fixtures.

---

## 4. State & Receipt-Log Inclusion Prover

Mosoo verifies arbitrary state facts against the authenticated `state_root` or `receipts_root` committed in a verified `HeaderRecord`:

1. **Account State Proofs:**
   - Traverses the Ethereum World State Trie (Merkle-Patricia Trie via `alloy-trie`).
   - Verifies `keccak256(account_address) -> RLP(nonce, balance, storageRoot, codeHash)`.
2. **Contract Storage Slot Proofs:**
   - Traverses the contract's dedicated Storage Trie rooted at `storageRoot`.
   - Verifies `keccak256(slot_key) -> RLP(slot_value)`.
3. **EIP-2718 Typed Transaction Receipt Logs:**
   - Traverses the Receipts Trie rooted at `receipts_root`.
   - Decodes Legacy, EIP-2930, EIP-1559, and EIP-4844 receipts.
   - Extracts event log emitter, topics (Topic 0 event signature + indexed arguments), and unindexed log data.

---

## 5. Dynamic Predicate Evaluation & Statement ID V2

### 5.1 Predicate Engine
Rather than forcing smart contracts to parse raw RLP payloads, Mosoo provides an in-guest predicate engine:
- `Equal(target)`: Value matches expected byte array or scalar.
- `AtLeast(min)`: Scalar integer $\ge$ minimum threshold (e.g. deposit amount $\ge 1.0$ ETH).
- `LessThan(max)`: Scalar integer $<$ maximum limit.
- `All(predicates)`: Conjunction of nested conditions.
- `Any(predicates)`: Disjunction of nested conditions.
- *Scheduled M2 Extensions:* `NotEqual` and bitwise-mask matching.

### 5.2 Canonical V2 Statement Identifier
To uniquely identify verified Ethereum facts and prevent duplicate claims across applications or chains, Mosoo computes:

$$\text{StatementID} = \text{SHA256}(\text{"mosoo\_statement\_v2"} \parallel \text{chain\_id} \parallel \text{genesis\_validators\_root} \parallel \text{subject\_key} \parallel \text{proof\_type\_tag} \parallel \text{verified\_value})$$

- `chain_id`: 8-byte little-endian Ethereum chain identifier (domain separation).
- `genesis_validators_root`: 32-byte beacon chain genesis root (network uniqueness).
- `subject_key`: 32-byte fact identifier (`keccak256(account || slot)` for storage; `keccak256(tx_hash || log_index)` for receipts).
- `proof_type_tag`: 1-byte proof tag (`0x01` = Account, `0x02` = Storage, `0x03` = Receipt Log).
- `verified_value`: 32-byte verified canonical state fact.

---

## 6. Isolated PDA State Account Model

Mosoo utilizes deterministic Program Derived Addresses (PDAs) under `MOSOO_PROGRAM_ID`:

| Account Type | Seed Derivation | Description |
|---|---|---|
| `InstanceAccount` | `["mosoo_instance", instance_id]` | Stores genesis roots, current/next sync committee roots, and weak subjectivity boundaries. |
| `HeaderRecord` | `["header", instance_id, slot_le8]` | Stores verified block roots (`state_root`, `receipts_root`, `execution_block_hash`). |
| `JobAccount` | `["update_job", instance_id, update_slot_le8]` | Stores intermediate BLS accumulator state between `BeginUpdate`, `MillerUpdate`, and `FinishUpdate`. |
| `NullifierAccount` | `["nullifier", statement_id]` | Created by consuming contracts to ensure single-use execution of verified statements. |

All state access scales strictly $O(1)$ via direct PDA addressability, with zero storage-dependent loops or tree degradation.

---

## 7. Autonomous Relayer Daemon (`mosoo-daemon`)

The background daemon operates continuously to keep LEZ light-client instances synchronized:
- **Autonomous Head Polling:** Polls configured Ethereum Beacon node REST endpoints (`/eth/v1/beacon/...`).
- **Randomized Polling Jitter:** Enforces randomized submission deferral (`1.0x` to `2.5x` poll interval) to avoid synchronized bursts across independent relayers.
- **Pre-Submission Idempotency Check:** Checks whether a finalized slot has already been processed before submitting updates.
- **Logos Core Verified Proxy:** Supports routing requests through a configured Logos Ethereum Core proxy endpoint (`LOGOS_ETHEREUM_CORE_RPC` / `--logos-ethereum-core-rpc`).
- **Structured Telemetry (`tracing`):** Emits structured JSON or pretty logs via `tracing-subscriber` (note: a dedicated HTTP Prometheus `/metrics` endpoint is on the production roadmap and not exposed in `daemon/src/main.rs` today).

---

## 8. Reference Consumers & Verification Flow

Reference consumer contracts (`erc20-receiver` and `ether-receiver`) demonstrate atomic same-transaction consumption:
1. Consumer receives the light client instance PDA, verified header, inclusion proof, predicate, and user parameters.
2. Consumer executes Cross-Program Invocation (CPI) into Mosoo verifier (`verify_statement`).
3. Mosoo verifies the MPT inclusion proof against the authenticated `HeaderRecord` and evaluates the predicate in-transaction (< 118,500 gas, ~140,000 zkVM cycles).
4. Consumer checks that `statement.chain_id == EXPECTED_CHAIN_ID` and `statement.predicate_holds == true`.
5. Consumer creates `NullifierAccount(["nullifier", statement_id])`; if the nullifier already exists, the transaction reverts atomically.
6. Consumer completes the authorized business action (mints equivalent tokens or credits native ledger).
