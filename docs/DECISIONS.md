# Mosoo Architectural Decision Records (ADRs)

This document records architectural decisions, threat models, and consensus invariants for the **Mosoo** Ethereum state attestation bridge on Logos Execution Zone (LEZ).

---

## Table of Contents
- [ADR-001: 3-Transaction Pipeline with Cryptographic Intermediate Commitments](#adr-001-3-transaction-pipeline-with-cryptographic-intermediate-commitments)
- [ADR-002: Strict Altair Light Client Committee Period Selection & Dynamic Handoff](#adr-002-strict-altair-light-client-committee-period-selection--dynamic-handoff)
- [ADR-003: Cryptographic RLP Block Header Root Derivation for Gloas ePBS](#adr-003-cryptographic-rlp-block-header-root-derivation-for-gloas-epbs)
- [ADR-004: Instance Immutability & Re-anchoring via Fresh Instance Initialization](#adr-004-instance-immutability--re-anchoring-via-fresh-instance-initialization)
- [ADR-005: Dual-Nullifier Architecture for Two-Way Bridge Double-Spend Immunity](#adr-005-dual-nullifier-architecture-for-two-way-bridge-double-spend-immunity)
- [ADR-006: Store-Backed Authenticity & Instance/Checkpoint Pinning](#adr-006-store-backed-authenticity--instancecheckpoint-pinning)
- [ADR-007: Fork-Aware Generalized Indices & Strict Network Validation](#adr-007-fork-aware-generalized-indices--strict-network-validation)
- [ADR-008: Statement ID V2, Salted Commitments & Privacy Boundaries](#adr-008-statement-id-v2-salted-commitments--privacy-boundaries)
- [ADR-009: Two-Way Bridge Escrow, Rolling Withdrawal Caps & Committee Governance](#adr-009-two-way-bridge-escrow-rolling-withdrawal-caps--committee-governance)
- [ADR-010: Rejected Pairing Alternatives & Stalled Job Leases](#adr-010-rejected-pairing-alternatives--stalled-job-leases)
- [ADR-011: Permissionless Daemon Liveness & Competing Updates](#adr-011-permissionless-daemon-liveness--competing-updates)

---

## ADR-001: 3-Transaction Pipeline with Cryptographic Intermediate Commitments

### Context & Problem Statement
Ethereum sync committee verification requires verifying an aggregate BLS12-381 signature over 512 validator public keys, computing two Miller loops, performing final exponentiation, and verifying generalized Merkle multi-proofs for beacon state and execution payload headers. In resource-constrained execution environments such as the Logos Execution Zone (LEZ) and zkVM guest execution (RISC Zero), executing the entire verification in a single atomic transaction can exceed the block gas limit (LEZ gas cap $\le 10,000,000$ gas) or zkVM cycle bounds.

### Decision
Mosoo implements a deterministic **3-Transaction Verification Pipeline** dividing work across distinct lifecycle stages:
1. `handle_begin_update`:
   - Validates instance initialization, monotonic slot advancement ($slot_{new} > slot_{current}$), and weak-subjectivity safety bound ($\Delta_{slot} \le 1,728,000$).
   - Computes sync committee periods and selects active signing committee (`current_sync_committee` vs `next_sync_committee`).
   - Parses the 64-byte bitfield, checks the participation quorum ($\ge 342 / 512$, i.e. $\ge 2/3$), and aggregates participating validator public keys into a single G1 curve point.
   - Computes the attested header signing root via fork-aware domain separation and maps it to G2 (`blst_hash_to_g2`).
   - Emits a cryptographic digest of the update:
     $$\text{update\_digest} = \text{SHA-256}(\text{SSZ}(\text{LightClientUpdate}))$$
   - Stores intermediate state in `JobAccount` at `JobStage::Miller`.
2. `handle_miller_update`:
   - Verifies instance chain ID, slot binding, stage precondition (`JobStage::Miller`), and asserts $\text{compute\_digest}(\text{job.update}) == \text{job.update\_digest}$.
   - Computes two Miller loops:
     $$M = e(P_{\text{agg}}, Q_{\text{msg}}) \cdot e(-G_1, \sigma)$$
   - Transitions `JobAccount` to `JobStage::Finish`.
3. `handle_finish_update`:
   - Enforces cross-stage digest integrity and executes final exponentiation:
     $$\text{final\_exp}(M) \stackrel{?}{=} 1_{\mathbb{G}_T}$$
   - Verifies the finality branch and committee handoff branches against the verified beacon state.
   - Authenticates execution payload headers and transitions `JobAccount` to `JobStage::Done`.

### Consequences & Guarantees
- **No Injected Intermediate State**: An attacker attempting to inject a malicious update into `handle_miller_update` or `handle_finish_update` is rejected with `JobDigestMismatch`.
- **Replay & Out-of-Order Immunity**: Attempting to invoke `handle_finish_update` on a `JobStage::Miller` or `JobStage::Done` job is rejected with `WrongJobStage`.

---

## ADR-002: Strict Altair Light Client Committee Period Selection & Dynamic Handoff

### Context & Problem Statement
Under the Ethereum Altair Light Client Sync Protocol, the active sync committee rotates every 256 epochs (8,192 slots, $\approx 27.3$ hours):
$$\text{period}(slot) = \lfloor slot / 8192 \rfloor$$
A light client tracking period $P$ must use `current_sync_committee` for signatures within period $P$, and `next_sync_committee` for signatures in period $P+1$. An attacker could attempt to submit signatures from an expired period 0 committee for a period 1 update, or skip periods entirely ($P \to P+2$), causing committee desynchronization.

### Decision
Mosoo enforces the canonical Altair Light Client committee selection and rotation invariants in `handle_begin_update` and `handle_finish_update`:
1. **Period Derivation**:
   $$P_{\text{store}} = \text{slot} / 8192, \quad P_{\text{sig}} = \text{signature\_slot} / 8192, \quad P_{\text{fin}} = \text{finalized\_slot} / 8192$$
2. **Signing Committee Selection**:
   - If $P_{\text{sig}} == P_{\text{store}}$: Verifier aggregates public keys from `instance.current_sync_committee`.
   - If $P_{\text{sig}} == P_{\text{store}} + 1$: Verifier aggregates public keys from `instance.next_sync_committee`, strictly requiring `next_sync_committee` to be pre-authenticated. If absent, rejected with `MissingCommitteeBranch`.
   - If $P_{\text{sig}} > P_{\text{store}} + 1$: Light client has skipped an intermediate rotation period. Verifier immediately rejects with `SyncCommitteePeriodSkip { sig_period, current_period }`.
   - If $P_{\text{sig}} < P_{\text{store}}$: Rejected as a stale update.
3. **Dynamic Rotation at Finalized Boundary**:
   In `handle_finish_update`, sync committee rotation occurs if and only if the **finalized header** advances into the next period ($P_{\text{fin}} > P_{\text{store}}$):
   $$\text{instance.current\_sync\_committee} \leftarrow \text{instance.next\_sync\_committee.take}()$$
   $$\text{instance.next\_sync\_committee} \leftarrow \text{update.next\_sync\_committee}$$
   Tying rotation strictly to finalized period advancement prevents premature committee rotation when an update is signed in period $P+1$ but the finalized header remains in period $P$. This guarantees that `instance.current_slot` and `instance.current_sync_committee` remain in lockstep across arbitrary sequential boundary updates.

### Security Properties
- Replaying a signature from period 0 to sign period 1 is cryptographically rejected by BLS pairing verification (`consensus_and_branches`).
- Period skip attacks are rejected before expensive pairing computation (`consensus_and_branches`).
- Multi-update sequential boundary transitions preserve committee synchronization invariants without desynchronization (`consensus_and_branches`).

---

## ADR-003: Cryptographic RLP Block Header Root Derivation for Gloas ePBS

### Context & Problem Statement
Under Ethereum's Gloas fork (ePBS / EIP-7732), the consensus beacon block body does not contain the full `ExecutionPayloadHeader`. Instead, at generalized index 2856, the beacon block body commits **only** to the execution `block_hash`:
$$\text{BeaconBlockBody.execution\_payload\_bid.block\_hash} \to \text{gindex } 2856$$
If a light client naively accepts caller-supplied `state_root` and `receipts_root` without cryptographic binding, an attacker can submit an authentic `block_hash` while substituting a forged `state_root`, minting unbacked tokens on LEZ.

### Decision
Per Logos RFP-021 Functionality #03, Mosoo requires the caller to provide the raw RLP-encoded execution block header (`execution_rlp`) for Gloas updates, and enforces strict fail-closed cryptographic root extraction:
1. Verifies the execution block hash Merkle inclusion branch:
   $$\text{compute\_branch\_root}(\text{payload\_header.block\_hash}, \text{branch}, 2856) == \text{finalized\_header.body\_root}$$
2. Asserts cryptographic equivalence of the RLP header:
   $$\text{keccak256}(\text{execution\_rlp}) \stackrel{?}{=} \text{payload\_header.block\_hash}$$
   If mismatched, verifier rejects with `GloasExecutionRlpMismatch`.
3. Parses the RLP item list according to the Ethereum Yellow Paper and extracts:
   - Field 3: `state_root` (32 bytes)
   - Field 5: `receipts_root` (32 bytes)
   - Field 8: `block_number` (scalar u64)
4. Validates that caller-supplied `payload_header.state_root` and `payload_header.receipts_root` (if non-zero) match the cryptographically derived roots exactly. If conflicting, verifier rejects with `ExecutionPayloadBranchInvalid`.

### Security Properties
- Zero blind trust in untrusted relayers or block builders.
- Attacker cannot tamper with state or receipt roots without breaking Keccak-256 collision resistance (`consensus_and_branches`).
- `HeaderRecord` execution root provenance: `InstanceAccount` commits to `current_execution_block_hash`, `current_execution_state_root`, and `current_receipts_root`. When state attestation executes, `handle_attest_state` asserts exact matching between caller-supplied `HeaderRecord` execution roots and the authenticated instance state, strictly rejecting forged execution roots under genuine beacon roots (`consensus_and_branches`).

---

## ADR-004: Instance Immutability & Re-anchoring via Fresh Instance Initialization

### Context & Problem Statement
Logos RFP-021 Functionality #13 mandates:
> *"The light client checkpoint is immutable. Stale instances that exceed the weak subjectivity threshold cannot be rewritten in-place."*

Allowing an in-place "recovery" instruction on an existing instance creates an attack surface where an operator or privileged caller can overwrite the verified consensus state, invalidating historical receipts and creating dual-state ambiguity.

### Decision
1. **Zero Checkpoint Mutation**:
   Mosoo eliminates `handle_recover_instance` and removes `Instruction::RecoverInstance` from the guest binary. Existing `InstanceAccount` checkpoints are strictly immutable.
2. **Re-anchoring via Fresh Instance (Functionality #10)**:
   When an instance has expired beyond the weak-subjectivity window ($\Delta_{slot} > 1,728,000$ slots / $\approx 240$ days), it is abandoned. Applications re-anchor by initializing a **fresh instance** via `handle_initialize` with a newly verified, trusted bootstrap checkpoint and current sync committee.
3. **Bootstrap Verification**:
   The fresh bootstrap checkpoint must be verified within the operational freshness window ($slot_{\text{head}} - slot_{\text{bootstrap}} \le 1,728,000$) and have its sync committee Merkle branch authenticated against $state\_root$.

### Security Properties
- Mathematical immutability of verified ledger checkpoints.
- Eliminates administrative privilege escalation and arbitrary checkpoint overwrite vulnerabilities (`instance_and_config`).

---

## ADR-005: Dual-Nullifier Architecture for Two-Way Bridge Double-Spend Immunity

### Context & Problem Statement
In cross-chain bridging (e.g., Native ETH $\to$ mETH on LEZ and mETH burn $\to$ ETH unlock), replay attacks can take two forms:
1. Re-submitting the exact same verified statement to claim tokens twice.
2. Tampering with the statement ID (e.g., flipping bits or generating a random UUID) while providing identical event logs or state proofs to bypass basic nullifier tracking.

### Decision
Mosoo implements a two-tier **Dual-Nullifier & Subject-Key Binding Protocol**:
1. **Cryptographic Subject-Key Derivation**:
   For each bridge event, consumers derive an immutable, deterministic `subject_key`:
   - Native ETH Deposits:
     $$\text{subject\_key} = \text{keccak256}(\text{"ETH\_DEPOSIT"} \parallel block\_hash \parallel tx\_idx \parallel log\_idx \parallel sender \parallel recipient \parallel wei)$$
   - ERC-20 Transfers:
     $$\text{subject\_key} = \text{keccak256}(\text{"ERC20\_TRANSFER"} \parallel block\_hash \parallel tx\_idx \parallel log\_idx \parallel token \parallel sender \parallel recipient)$$
2. **Atomic Verification & Nullification**:
   When `claim_ether` or `claim_erc20_transfer` executes:
   - Asserts $\text{statement.subject\_key} == \text{derived\_subject\_key}$.
   - Asserts $\text{statement.header\_hash}$ is recorded in the verified `HeaderRecord` store.
   - Asserts $\text{nullifiers.is\_used}(\text{statement.statement\_id}) == \text{false}$.
   - Asserts $\text{nullifiers.is\_used}(\text{derived\_subject\_key}) == \text{false}$.
   - Records both `statement.statement\_id` and `derived\_subject\_key` as consumed in persistent storage.
3. **Reverse Burn Receipt Authentication**:
   When burning tokens on LEZ to unlock on Ethereum, the contract emits a deterministic `burn_id`:
   $$\text{burn\_id} = \text{keccak256}(\text{"METH\_BURN"} \parallel burner \parallel recipient \parallel amount \parallel lez\_slot \parallel nonce)$$
   The Ethereum unlock contract validates `burn_id` against consumed nullifiers, preventing replay across both directions.

### Security Properties
- Complete immunity against statement ID malleability (`state_and_replay`).
- Complete immunity against duplicate event log claims across different blocks or identical slots (`state_and_replay`).

---

## ADR-006: Store-Backed Authenticity & Instance/Checkpoint Pinning

### Context
If consensus handlers or consumers deserialize `InstanceAccount` or `HeaderRecord` payloads directly from untrusted transaction calldata, callers can forge committees, stale slots, or synthetic headers without executing consensus verification.

### Decision
- Guest dispatchers and consumer entrypoints load light-client accounts from program-owned `AccountStore` storage (`store.get_account_owner == MOSOO_PROGRAM_ID`) rather than accepting mutable caller structs.
- `JobAccount` PDAs derive deterministically from `(instance_id, job_id)` and verify `chain_id`, `instance_id`, and `update_digest` across `begin_update -> miller_update -> finish_update`.
- `TrustedBridgeConfig::load_strict` pins expected `instance_pda`, trusted checkpoint roots, trusted lockers (`MosooLocker` v1/v2 on Sepolia), and token allowlists; consumers track independent `instance_trusted_heads` per instance PDA and validate fresh checkpoints against the active weak-subjectivity ceiling (`54,000` operational slots / `1,728,000` hard cap).

---

## ADR-007: Fork-Aware Generalized Indices & Strict Network Validation

### Context
Ethereum Altair, Capella/Deneb, Electra/Fulu, and Gloas ePBS use distinct `BeaconState` / `BeaconBlockBody` layouts and SSZ generalized indices. Accepting unvalidated chain overrides on built-in networks can bypass genesis roots or fork versions.

### Decision
- [`mosoo-core/src/crypto.rs`](../mosoo-core/src/crypto.rs) resolves `current_sync_committee`, `next_sync_committee`, `finalized_root`, `block_roots`, and execution payload generalized indices dynamically per chain and slot.
- `is_supported_chain_or_configured(chain_id, config)` permits custom `NetworkConfig` for non-built-in chains (`genesis_validators_root != 0`), while on built-in canonical chains (`1`, `11155111`, `17000`, `560048`) it rejects mismatched `chain_id`, spoofed non-zero `genesis_validators_root`, or fork-version overrides.
- Real Ethereum chain JSON fixtures under `vectors/` (Mainnet Fulu, Sepolia Gloas/`DepositCommitted`, Hoodi Fulu) verify consensus parsing and MPT proofs in `real_chain_vectors_tests.rs`.

---

## ADR-008: Statement ID V2, Salted Commitments & Privacy Boundaries

### Context
Binding a nullifier to predicate thresholds lets an attacker replay the same event with a modified threshold (e.g. `AtLeast(1)` vs `AtLeast(2)`). Meanwhile, logging `lezRecipient` or plaintext amounts on Ethereum exposes deposit linkage.

### Decision & Known Boundaries
- `derive_statement_id_v2` derives nullifiers strictly from `(chain_id, genesis_validators_root, source_instance_pda, subject_key, proof_type_tag, verified_value)` — completely invariant to the predicate evaluated.
- `PrivacyMode::Confidential` blinds `StatementAccount` data with explicit non-zero caller salt (`privacy_salt`), while `MosooLocker` v2 adds `depositShieldedETH` / `DepositCommitted` (without `lezRecipient`), a Depth-20 commitment Merkle tree, and `strictFixedDenominationMode`.
- **Honest Boundary:** LEZ consumers currently verify shielded preimages and receipt proofs directly in Rust rather than inside an anonymous Groth16 circuit; hiding `tx_index`/`log_index` and Merkle paths behind zero-knowledge proofs on public LEZ remains future RFP-022 work.

---

## ADR-009: Two-Way Bridge Escrow, Rolling Withdrawal Caps & Committee Governance

### Context
Outbound settlement from LEZ back to Ethereum (`contracts/MosooLocker.sol`) cannot yet verify LEZ Bedrock consensus state directly on L1 without an L1 ZK verifier contract, so outbound unlocks must limit operator risk defensively.

### Decision & Known Boundaries
- Outbound `unlockShieldedETH` / `unlockETH` routes require `M-of-N` EIP-712 attester signatures (live Sepolia v2 commissioned at `2-of-2`), EIP-2 low-`s` checks, contract-scoped `DOMAIN_SEPARATOR`, `executedBurns` nullifiers, rolling 24h withdrawal rate limits (`MAX_CLEANUP_BATCH = 32`), 24h queue + Guardian veto for large withdrawals (`>= 10 ETH`), 24h `attesterAuthority` delay, and 48h multisig governance timelocks (`GOVERNANCE_TIMELOCK_DELAY = 2 days`).
- Inbound RFP-021 acceptance remains completely independent of outbound `MosooLocker` bridge assumptions.

---

## ADR-010: Rejected Pairing Alternatives & Stalled Job Leases

### Context
In addition to selecting the 3-transaction verification pipeline (ADR-001), the team evaluated alternative verification architectures and crash-recovery behavior when an operator stops mid-pipeline.

### Rejected Alternatives & Recovery Design
- **Host-Level BLS12-381 Precompiles:** Rejected because requiring custom host precompiles blocks immediate deployment on unmodified LEZ runtimes (`v0.3.1` / `v0.4`).
- **Unaccelerated Pure-Rust BLS (`arkworks` without assembly):** Rejected after zkVM cycle profiling showed pairing arithmetic exceeding 28M cycles, whereas assembly-accelerated `blst` fits comfortably inside the 3-tx budget (`~9.35M` cycles total; ~350k aggregate overhead vs a hypothetical single transaction due to base fees and intermediate `JobAccount` storage).
- **Off-Chain SNARK/STARK Proof of Consensus Verification:** Rejected to avoid multi-minute prover latency and centralized prover infrastructure for routine consensus header progression.
- **Stalled `JobAccount` Recovery:** Each `JobAccount` carries a nonce and lease window so any independent operator can finish a stalled job (`Miller` -> `Finish`) or start a newer slot once the lease expires.

---

## ADR-011: Permissionless Daemon Liveness & Competing Updates

### Context
Mosoo runs without a sequencer leader-election lock coordinator for Ethereum header updates. Independent `mosoo-daemon` operators may race to advance finality.

### Decision
- **Soft-Success Collision Handling:** When `BeginUpdate` finds a slot job already open (`SubmitResult::JobAlreadyOpen`), the daemon treats it as non-fatal, logs it cleanly, and waits for the next poll cycle rather than competing or burning gas.
- **Submission Jitter:** Operators apply randomized backoff (`wait_time = poll_interval * uniform_random(1.0, 2.5)`) instead of external lock services, keeping liveness permissionless with negligible wasted `BeginUpdate` collisions (covered in `daemon/src/tests.rs`).
