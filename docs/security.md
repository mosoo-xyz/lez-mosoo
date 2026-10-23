# Mosoo Security Threat Model & Analysis

This document details the threat model, security assumptions, and mitigation strategies for the **Mosoo** trustless Ethereum state attestation module for the Logos Execution Zone (LEZ), adhering to the security requirements outlined in **RFP-021**.

---

## 1. Trust Assumptions & Boundary

1. **Ethereum Consensus (Altair+)**: We assume at least 2/3 of Ethereum's 512-validator sync committee is honest at any given epoch. If > 1/3 of the committee is malicious, safety can be violated on Ethereum itself.
2. **Weak-Subjectivity Anchor**: An instance is bootstrapped with a trusted checkpoint (`bootstrap_header`, `current_sync_committee`, `current_sync_committee_branch`). The initial 512-validator sync committee is cryptographically proven against `bootstrap_header.state_root` at fork-aware generalized indices (54 for Altair/Deneb, 86 for Electra/Fulu, 2945 for Gloas). The bootstrap checkpoint must satisfy weak-subjectivity freshness bounds (within 1,728,000 slots of the trusted network head).
3. **RISC0 zkVM Correctness**: The underlying zkVM correctly enforces the RISC-V instruction set and STARK/SNARK verification logic.

---

## 2. Attack Vectors & Mitigations

### 2.1 Fabricated-Chain Attack (Fake Headers)
* **Attack**: An adversary submits forged Beacon block headers with arbitrary execution roots to claim non-existent token deposits or state changes.
* **Mitigation**:
  - Updates require aggregate BLS12-381 signatures verified against the active 512-validator `SyncCommittee`.
  - Participation is strictly enforced to be >= 342 validators (ceil(512 * 2/3)). Any update with < 342 signatures is rejected with `InsufficientParticipation`.
  - Signatures are verified using optimized `blst` pairing cryptography over the calculated `signing_root` across the 3-transaction pipeline.
  - Complete fork-version schedule protects all signing domains across Mainnet and Sepolia including Deneb, Electra (`0x05000000`), Fulu (`0x06000000`), and Gloas (`0x90000077`).

### 2.2 Committee-Handoff Hijacking
* **Attack**: At sync committee rotation boundaries (every 8,192 slots / 256 epochs / ~27.3 hours), an attacker attempts to inject a malicious sync committee of their own choosing.
* **Mitigation**:
  - Rotations require a cryptographic Merkle branch proof (`next_sync_committee_branch`) anchored directly into the attested state root of the finalized header.
  - The branch verifies against the fork's generalized index (55 for Altair/Deneb, 87 for Electra/Fulu, 2946 for Gloas) in `BeaconState`.
  - An attacker cannot substitute `next_sync_committee` without forging the current committee's signature.

### 2.3 Checkpoint Staleness & Long-Range Reorganization
* **Attack**: An attacker attempts to submit an outdated finalized header or roll back the LEZ instance's tracked head to a past fork.
* **Mitigation**:
  - Monotonic head progression: `update.finalized_header.slot > instance.current_slot` is strictly asserted (`StaleUpdate`).
  - Stale instances that fall outside the weak-subjectivity window (1,728,000 slots) require recovery via `handle_recover_instance` rather than incremental mutation from historical state.

### 2.4 State Inclusion & Fake Execution Root Injection
* **Attack**: A consumer dApp caller supplies an arbitrary execution state root to falsely prove an account balance or storage slot.
* **Mitigation**:
  - `HeaderRecord.execution_state_root`, `execution_block_hash`, and `receipts_root` are extracted from `ExecutionPayloadHeader` and cryptographically verified against `BeaconBlockHeader.body_root` via an SSZ Generalized Index 25 Merkle branch proof inside the zkVM guest (or generalized index 2856 for Gloas ePBS execution block hash).
  - Execution payload header and branch are **mandatory** on post-Merge Ethereum: zero-root fallback (`[0; 32]`) is strictly rejected (`MissingExecutionPayload`).
  - `verify_state_proof` accepts only an authenticated on-chain `HeaderRecord` PDA written by the attester program during a successful `finish_update` transaction.
  - Callers cannot pass arbitrary roots.
  - Merkle-Patricia Trie (MPT) proofs are verified against `header_record.execution_state_root` via `alloy-trie`.

### 2.5 Receipt & Event Log Forgery
* **Attack**: An attacker fabricates an ERC-20 `Transfer` deposit receipt or modifies the recipient / token amount to steal funds.
* **Mitigation**:
  - Receipt inclusion is verified against `header_record.receipts_root` via Merkle-Patricia Trie proofs (`verify_receipt_log_proof`).
  - EIP-2718 typed transaction envelopes (0x01, 0x02, 0x03) and legacy receipts are decoded and validated.
  - Emitting contract address and event signature topics (`keccak256("Transfer(address,address,uint256)")`) are asserted, rejecting mismatched emitters (`EventEmitterMismatch`) and forged event signatures (`EventTopicMismatch`).
  - Out-of-bounds log indices are rejected (`LogIndexOutOfBounds`).

### 2.5 Cross-Chain Replay & Chain-ID Spoofing
* **Attack**: An attacker takes a valid deposit made on Sepolia testnet and replays the proof to claim tokens on an Ethereum Mainnet LEZ instance.
* **Mitigation**:
  - Domain separation: `compute_signing_root` incorporates `compute_sync_committee_domain(chain_id, slot)` using network-specific `fork_version` and `genesis_validators_root`.
  - A Sepolia BLS signature is cryptographically invalid when evaluated under Mainnet domain parameters.
  - `VerifiedStatement` includes `chain_id`, and consumers explicitly assert `statement.chain_id == ETH_MAINNET_CHAIN_ID`.

### 2.6 Double-Spending / Cross-Slot Statement Replay
* **Attack**: A user re-submits a valid `VerifiedStatement` multiple times or generates proofs at different block slots for the same static balance to mint tokens repeatedly.
* **Mitigation**:
  - `statement_id` is derived deterministically:
    ```text
    statement_id = sha256(chain_id || subject_key || proof_type || value || predicate)
    ```
  - The `subject_key` is bound to the immutable on-chain identity (account address or contract + storage slot) rather than the ephemeral block slot. Proving the same balance across different slots produces the identical nullifier.
  - Any consuming program (such as `erc20-receiver` or `ether-receiver`) records `statement_id` into a dedicated Nullifier PDA.
  - Subsequent claims with the same `statement_id` immediately revert with `AlreadyClaimed`.

### 2.7 Front-Running & Duplicate Submission (Gas Griefing)
* **Attack**: Multiple permissionless daemons observe a new finalized block and submit simultaneous `Begin` transactions, causing wasted gas for trailing operators.
* **Mitigation**:
  - The `mosoo-daemon` incorporates randomized delay jitter (1.0x to 2.5x poll interval).
  - The LEZ contract validates that if an existing job is in progress or already finalized for that slot, redundant submissions are skipped idempotently.

### 2.8 Weak-Subjectivity Bootstrap Poisoning & Stale Instances
* **Attack**: An operator initializes a Mosoo instance from a checkpoint outside the Ethereum weak-subjectivity period, allowing a long-range reorganization to substitute an attacker-controlled committee.
* **Mitigation**:
  - `handle_initialize` checks `trusted_head_slot - bootstrap_header.slot <= 1,728,000` (~240 days max bound, with ~14-30 day operational recommendation).
  - `handle_begin_update` enforces: `update.finalized_header.slot <= instance.current_slot + 1,728,000`, rejecting stale updates with `WeakSubjectivityExpired`.
  - Stale instances stalled past this window can be safely re-anchored using `handle_recover_instance`.
  - Public Ethereum checkpoint sync services (e.g., Lodestar Checkpoint Sync) provide verifiable checkpoint sources.

### 2.9 Competing-Update Race Condition (Liveness Under Concurrent Operators)
* **Attack**: Two operators both observe a new finalized slot and submit `BeginUpdate` simultaneously. The trailing operator's submission creates a conflicting `JobAccount` or overwrites in-progress pairing state, corrupting the verification pipeline.
* **Mitigation**:
  - The `JobAccount` PDA is keyed by `[instance_pubkey, nonce]`. Only the first `BeginUpdate` for a given slot successfully creates the PDA; subsequent attempts detect an existing open job and return `JobAlreadyOpen`.
  - The daemon detects `JobAlreadyOpen` and silently skips, waiting for the next poll cycle.
  - The 3-transaction pipeline (`Begin` → `Miller` → `Finish`) is strictly sequential per job nonce; interleaving is impossible by protocol.
  - A detailed description of the competing-update recovery flow is documented in [`docs/DAEMON.md`](DAEMON.md) (Section 8).

### 2.10 zkVM Proof Soundness & Guest Binary Integrity
* **Attack**: An operator substitutes a modified guest binary that skips BLS verification or relaxes quorum thresholds, producing fraudulent `HeaderRecord` PDAs accepted by consumers.
* **Mitigation**:
  - The RISC0 zkVM produces a cryptographic STARK proof of correct execution of the pinned guest binary.
  - The LEZ attester program verifies the proof against the pinned **guest image ID** (derived from guest binary digest `01ab35fda434...`); any modification to the guest binary produces a different image ID and is rejected.
  - Reproducible guest builds are documented in [`docs/REPRODUCE.md`](REPRODUCE.md): anyone can rebuild the identical binary and verify the SHA-256 digest independently.

---

## 3. Security Assumptions Summary

| Assumption | Condition | Consequence of Violation |
| :--- | :--- | :--- |
| Ethereum sync committee honesty | ≥ 2/3 of 512-validator committee is honest | Safety violated on Ethereum itself (not Mosoo-specific) |
| Weak-subjectivity bootstrap | Bootstrap checkpoint within ~2-week window | Long-range re-org possible for attacker-controlled initial committee |
| RISC0 zkVM soundness | Underlying STARK/SNARK prover is sound | Fraudulent proofs could pass verification |
| Guest binary integrity | Pinned image ID used in verification | Modified guest could bypass checks (prevented by image ID pinning) |
| LEZ account model correctness | PDA derivation and account ownership enforced by LEZ runtime | Attacker could substitute unauthorized account state |

---

## 4. Out-of-Scope Items (RFP-021 Explicit Exclusions)

Per Logos RFP-021 specification:

- **BLS12-381 host precompiles**: Adding VM-level precompiles is explicitly out of scope. Mosoo's in-guest `blst` execution is the RFP-compliant approach.
- **General Ethereum full-node security**: Mosoo is a light-client protocol; full-node eclipse attacks are outside its threat surface.
- **Consumer contract logic bugs**: The reference consumers (`erc20-receiver`, `ether-receiver`) demonstrate integration patterns; production deployments should conduct independent audits of their custom consumer logic.
