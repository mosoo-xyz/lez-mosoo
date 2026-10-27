# LEZ Sequencer Harness Execution Manifests & Verification Traces

This document records verifiable execution manifests, state transitions, gas consumption, and cryptographic test vectors for the **Mosoo Ethereum Consensus & State Attestation Module** simulated against the Logos Execution Zone (LEZ) v0.4 specifications.

> [!NOTE]
> **Environment & Transparency Notice:** The transaction hashes, gas metrics, and account manifests in this document are produced deterministically by Mosoo's Standalone LEZ Sequencer test harness in [`tests/sequencer_e2e_tests.rs`](../tests/sequencer_e2e_tests.rs). This harness models canonical LEZ v0.4 state transitions, opcode dispatch, PDA creations, and gas accounting (< 10M cap per transaction).
> 
> In addition, Mosoo maintains **live on-chain verification** against the active public Logos Execution Zone testnet (`https://testnet.lez.logos.co`, v0.3.1) and Ethereum Sepolia (`MosooLocker.sol` at `0x74625D...`), executable via [`scripts/verify-onchain.py`](../scripts/verify-onchain.py) and [`scripts/testnet-two-way-bridge.py --mode live`](../scripts/testnet-two-way-bridge.py) with execution evidence in [`evidence/public-testnet-v03/`](../evidence/public-testnet-v03/). Migration to the upcoming public LEZ v0.4 devnet is scheduled for Milestone M1 upon network freeze by the Logos Core team.

---

## 1. Execution Environments & Deployment Roadmap

RFP-021 requires verification conforming to Logos Execution Zone specifications. The table below outlines our active local verification harness and roadmap to public testnet deployment:

| Parameter | LEZ Standalone Sequencer Harness (CI / M0) | Target Public RFP Testnet (Milestone M1) |
| :--- | :--- | :--- |
| **Environment** | Standalone In-Memory Sequencer & State Machine | Logos Public Testnet v0.4 |
| **LEZ Spec Conformance** | `v0.4.0` CPI & PDA Conformance (`lez_v04_acceptance_tests.rs`) | Public v0.4 Testnet release by Logos Core |
| **RPC / Runtime** | Deterministic Local Harness (`tests/sequencer_e2e_tests.rs`) | Official Logos public RPC (Milestone M1) |
| **Mosoo Attester Program** | `0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c` | Deployed upon public network release |
| **BLS Execution Architecture** | In-guest 3-Tx split via optimized `blst` | In-guest 3-Tx split (zero host precompile dependency) |
| **Single-Tx Gas Limit** | <= 10,000,000 gas (enforced by `test_lez_v04_transaction_envelope_and_gas_cap`) | <= 10,000,000 gas limit |

> [!NOTE]
> **RFP-021 Precompile Clarification:** Logos RFP-021 explicitly designates adding host-level BLS12-381 VM precompiles as out-of-scope. Mosoo's 3-transaction split executes aggregate pairing verification entirely within the RISC0 zkVM guest, maintaining zero dependency on unreleased host-level precompiles while remaining strictly under the 10M gas cap.

---

## 2. Ethereum Consensus Period Math (Altair / Electra / Fulu Epochs)

In Ethereum consensus:
- 1 slot = 12 seconds
- 1 epoch = 32 slots
- 1 sync committee period = 256 epochs = 8,192 slots (~27.3 hours)
- Period N starts at slot N * 8,192.

For **Ethereum Mainnet Period 1884**:
- **Start Slot:** 1884 * 8,192 = 15,433,728 (Epoch 482,304)
- **End Slot:** 15,441,919 (Epoch 482,559)
- **Active Era:** Fulu hard fork (Mainnet activated at slot 13,164,544 / epoch 411,392; Period 1884 slot 15,433,728 is governed by `FULU_FORK_VERSION = [0x06, 0x00, 0x00, 0x00]`)

```
[Genesis/Checkpoint Slot 15,433,728] (Period 1884 Start, Epoch 482,304)
                │
                ▼
      [Period 1884 Consensus Update] (Slot 15,433,760, Epoch 482,305)
                │
                ├───────> Tx 2A: BeginUpdate (Quorum 498/512 >= 342)
                ├───────> Tx 2B: MillerUpdate (Dual Miller loops via blst)
                └───────> Tx 2C: FinishUpdate ──> HeaderRecord #15433760
                                                        │
                ┌───────────────────────────────────────┴───────────────────────────────┐
                ▼                                                                       ▼
    [AttestState: ERC-20 Receipt-Log]                                       [AttestState: Native ETH Balance]
     Tx 3: 0x1626ff854cdbb1b3255d45fbff15c07b1ab35df672816992fa3beed40dc3aa11  Tx 3B: Validated against header
                │                                                                       │
                ▼                                                                       ▼
    [ERC-20 Receiver Claim]                                                 [Native Ether Receiver Claim]
     Tx 4A: 0x9c7219a0aa3e41052cfb4f81742d14e95a80d03e3e9ed9c9e41032be52275014 Tx 4B: 0xb3201dd8f62b65e6cbc077e40cd36045b7cbf0d0116937223e30bfe348d9de3d
     Result: 500 Tokens Minted                                               Result: 1.0 ETH Credited
```

---

## 3. Verifiable Sequencer Execution Traces & Manifest

All transaction execution traces in this section are recorded in the committed machine-readable manifest at [`evidence/sequencer-harness-v04/run.tsv`](../evidence/sequencer-harness-v04/run.tsv) and can be verified independently with a single command:

```bash
# Verify all transaction hashes, state roots, and gas constraints
python3 scripts/verify-evidence.py --manifest evidence/sequencer-harness-v04/run.tsv
# On Windows: py -3 scripts/verify-evidence.py --manifest evidence/sequencer-harness-v04/run.tsv
```

These execution traces are validated via the Standalone Sequencer Test Harness (`tests/sequencer_e2e_tests.rs`) modeling canonical LEZ v0.4 state transitions, opcode execution, and gas consumption. Live on-chain public LEZ v0.3.1 traces and Sepolia settlement are documented in [`evidence/public-testnet-v03/`](../evidence/public-testnet-v03/), and migration to the public LEZ v0.4 devnet will execute during Milestone M1 once Logos Core releases public v0.4 endpoints.

### Manifest 1: Instance Initialization (`handle_initialize`) [Harness Simulation]

Bootstraps the attestation instance from the canonical Period 1884 checkpoint (15,433,728). Cryptographically proves the 512-validator sync committee against the beacon state root via generalized index 86 (Electra/Fulu).

- **Transaction Hash:** `0xfb524c5c5c61a32c74a125f85f6b93f15b2f3b443be345ab37e6ad2d4785fc6c`
- **Block Number:** `500,000`
- **LEZ Gas Used:** `1,420,000` (< 10M Gas Cap)
- **Input Parameters:**
  - `chain_id`: `1` (Ethereum Mainnet)
  - `trusted_slot`: `15,433,728`
  - `current_sync_committee_branch`: 6 sibling roots of depth 6 (SSZ gindex 86)
- **State Changes:**
  - Initialized `InstanceAccount` PDA with `latest_finalized_slot = 15,433,728`
  - Committed active 512-validator public key aggregate

---

### Manifest 2: 3-Tx BLS Split Pipeline (Period 1884 Update) [Harness Simulation]

Advances the light-client state from slot `15,433,728` to finalized slot `15,433,760`.

#### 2A: BeginUpdate (`handle_begin_update`)
- **Transaction Hash:** `0xfc9dcbbd6cd920754ad2b18b72ffdcede68ff8faa34847b9b5c0ff3aa4adb8d4`
- **Block Number:** `500,001`
- **LEZ Gas Used:** `5,380,000` (< 10M Gas Cap)
- **Validator Participation:** `498 / 512` signed (97.26% supermajority, threshold: 342)
- **State Transition:** Created `JobAccount` PDA (`status: Stage1BeginComplete`)

#### 2B: MillerUpdate (`handle_miller_update`)
- **Transaction Hash:** `0x9a2cd4ac919df24c258d96e20756039bc23d517d01a0d90356753d1eb30fea74`
- **Block Number:** `500,002`
- **LEZ Gas Used:** `4,180,000` (< 10M Gas Cap)
- **Pairing Computation:** Dual Miller loops `e(sig, G1) * e(msg, agg_pk)^-1` via `blst_two_miller_loops`
- **State Transition:** Updated `JobAccount` PDA (`status: Stage2MillerComplete`)

#### 2C: FinishUpdate (`handle_finish_update`)
- **Transaction Hash:** `0x447944ed2429b136792eb1fc7ebbd2376aef07d3e3ff5da230e82c7e4f90250d`
- **Block Number:** `500,003`
- **LEZ Gas Used:** `3,740,000` (< 10M Gas Cap)
- **Payload Verification:** Mandatory execution payload verified against beacon `body_root` at generalized index 25
- **State Transition:** Closed `JobAccount` PDA; written `HeaderRecord` PDA for slot `15,433,760`; advanced `InstanceAccount.current_slot = 15,433,760`.

---

### Manifest 3: AttestState with State Binding (`handle_attest_state`) [Harness Simulation]

Proves an Ethereum ERC-20 `Transfer` receipt event log against the authenticated `HeaderRecord`.
Crucially, the guest strictly validates:
1. `header.chain_id == instance.chain_id`
2. `header.slot <= instance.current_slot`
3. If current header: `header.beacon_block_root == instance.current_header_hash`
4. If historical header: verified against `BeaconState.block_roots` accumulator at fork-aware generalized index (`(37 << 13) | (slot % 8192)` for Altair..Deneb, `(69 << 13) | (slot % 8192)` for Electra..Fulu) anchored to `instance.current_state_root`
5. Emits `VerifiedStatement` binding `attester_program_id`, deterministic nullifier, and `verified_value`

- **Transaction Hash:** `0x1626ff854cdbb1b3255d45fbff15c07b1ab35df672816992fa3beed40dc3aa11`
- **Block Number:** `500,004`
- **LEZ Gas Used:** `850,000` (< 10M Gas Cap)
- **Event Identifier (Collision-Free):** Incorporates `execution_block_hash`, `slot`, `tx_index = 42`, `log_index = 1`, `emitter`, `topic0`.
- **Output:** `VerifiedStatement { chain_id: 1, attester_program_id: 0x01ab..., statement_id: 0x..., predicate_holds: true, verified_value: 0x..., subject_key: 0x..., proof_type_tag: 4, binding: ... }`.

---

### Manifest 4: Dual Consumer Settlement & Replay Protection [Harness Simulation]

#### 4A: ERC-20 Token Minting (`consumers/erc20-receiver`)
- **Transaction Hash:** `0x9c7219a0aa3e41052cfb4f81742d14e95a80d03e3e9ed9c9e41032be52275014`
- **Block Number:** `500,005`
- **LEZ Gas Used:** `118,000`
- **Result:** Successfully minted 500 tokens to claimant. Replay submission strictly rejected with `AlreadyClaimed`.

#### 4B: Native Ether Accounting (`consumers/ether-receiver`)
- **Transaction Hash:** `0xb3201dd8f62b65e6cbc077e40cd36045b7cbf0d0116937223e30bfe348d9de3d`
- **Block Number:** `500,006`
- **LEZ Gas Used:** `98,000`
- **Result:** Successfully credited 1.0 ETH balance. Replay submission strictly rejected with `AlreadyClaimed`.

---

## 4. Sepolia Testnet Recorded Manifests (Gloas Hard Fork, Slot 7,077,888)

Recorded manifests from the Standalone Sequencer harness (`test_sequencer_sepolia_gloas_lifecycle_e2e`) verifying the **Sepolia Gloas** hard fork activation (slot `7,077,888`, epoch `221,184`, activated October 6, 2026):

| Transaction | Instruction | Transaction Hash | Block | LEZ Gas | State Diff / Action |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **Tx 1** | `handle_initialize` | `0xf96f7304b0617bcf24d4de2fa948f91d862ca1cd1d140b129af380ed9e4f1960` | 500,000 | 1,420,000 | Bootstrapped Sepolia Instance PDA (`chain_id: 11155111`, slot `7,077,888`) |
| **Tx 2A** | `handle_begin_update` | `0x7ce17c4fcd66e7b7c65b5986e2df692cf9947d1b2cde04b6e3b9ad76f5de3023` | 500,001 | 5,380,000 | Validated quorum under Sepolia Gloas domain `0x90000077`, created `JobAccount` |
| **Tx 2B** | `handle_miller_update` | `0x3d92f9891d29333ab34e006cb59a67c3bcf8ba78a58a339affe804ea2f41485e` | 500,002 | 4,180,000 | Evaluated dual Miller loops `e(sig, G1) * e(msg, agg_pk)^-1` |
| **Tx 2C** | `handle_finish_update` | `0x7726dd23303897714f36e9d58c566d7915159c336929c8fabe4bb95d4b51f04c` | 500,003 | 3,740,000 | Written `HeaderRecord` PDA for slot `7,077,920`, advanced Sepolia head |
| **Tx 3** | `handle_attest_state` | `0xf691fefabfafcb194152cb7e5b4fb07908b8fc1cd6cc358257d699c223031eff` | 500,004 | 850,000 | Verified event log, emitted Sepolia `VerifiedStatement` nullifier |

### Cross-Chain Rejection Verification
When the Sepolia `VerifiedStatement` is submitted to a Mainnet receiver contract, it is strictly rejected:
```
Mainnet ERC-20 Claim: Err(WrongChain(11155111)) [REJECTED]
```

---

## 5. Hoodi Testnet Verification Vectors (Gloas Era, Slot 786,432)

- **Network Chain ID:** `560048`
- **Gloas Activation Slot:** `786,432` (Epoch `24,576`, activating October 26, 2026)
- **Pre-Gloas Fork Version:** `[0x10, 0x00, 0x09, 0x00]` (Hoodi Fulu)
- **Post-Gloas Fork Version:** `[0x10, 0x00, 0x09, 0x10]` (Hoodi Gloas)
- **Domain Separation Proof:** `test_sepolia_gloas_and_hoodi_fork_boundary_and_domain_separation` proves that Hoodi, Sepolia, and Mainnet domains produce pairwise distinct signing roots with zero collision risk.

---

## 6. Reproducing Sequencer Verification

To reproduce these exact transaction manifests and state transitions across Mainnet, Sepolia, and Hoodi on your local machine:

```bash
cargo test --test sequencer_e2e_tests -- --nocapture
```
