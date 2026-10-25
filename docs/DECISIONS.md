# Mosoo Architectural Decision Records (ADRs)

This document formalizes the key architectural decisions, threat models, design rationales, and consensus invariants underpinning the **Mosoo** trustless Ethereum state attestation bridge for Logos Execution Zone (LEZ), developed in accordance with **Logos RFP-021**.

---

## Table of Contents
- [ADR-001: 3-Transaction Pipeline with Cryptographic Intermediate Commitments](#adr-001-3-transaction-pipeline-with-cryptographic-intermediate-commitments)
- [ADR-002: Strict Altair Light Client Committee Period Selection & Dynamic Handoff](#adr-002-strict-altair-light-client-committee-period-selection--dynamic-handoff)
- [ADR-003: Cryptographic RLP Block Header Root Derivation for Gloas ePBS](#adr-003-cryptographic-rlp-block-header-root-derivation-for-gloas-epbs)
- [ADR-004: Instance Immutability & Re-anchoring via Fresh Instance Initialization](#adr-004-instance-immutability--re-anchoring-via-fresh-instance-initialization)
- [ADR-005: Dual-Nullifier Architecture for Two-Way Bridge Double-Spend Immunity](#adr-005-dual-nullifier-architecture-for-two-way-bridge-double-spend-immunity)

---

## ADR-001: 3-Transaction Pipeline with Cryptographic Intermediate Commitments

### Context & Problem Statement
Ethereum sync committee verification requires verifying an aggregate BLS12-381 signature over 512 validator public keys, computing two Miller loops, performing final exponentiation, and verifying generalized Merkle multi-proofs for beacon state and execution payload headers. In resource-constrained execution environments such as the Logos Execution Zone (LEZ) and zkVM guest execution (RISC Zero), executing the entire verification in a single atomic transaction can exceed the block gas limit (LEZ gas cap $\le 30,000,000$) or zkVM cycle bounds.

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
- Replaying a signature from period 0 to sign period 1 is cryptographically rejected by BLS pairing verification (tested in Attack 27).
- Period skip attacks are rejected before expensive pairing computation (tested in Attack 25).
- Multi-update sequential boundary transitions preserve committee synchronization invariants without desynchronization (tested in Attack 32).

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
- Attacker cannot tamper with state or receipt roots without breaking Keccak-256 collision resistance (tested in Attacks 29 and 30).
- `HeaderRecord` execution root provenance: `InstanceAccount` commits to `current_execution_block_hash`, `current_execution_state_root`, and `current_receipts_root`. When state attestation executes, `handle_attest_state` asserts exact matching between caller-supplied `HeaderRecord` execution roots and the authenticated instance state, strictly rejecting forged execution roots under genuine beacon roots (tested in Attack 31).

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
- Eliminates administrative privilege escalation and arbitrary checkpoint overwrite vulnerabilities (tested in Attack 19).

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
- Complete immunity against statement ID malleability (tested in Attack 18).
- Complete immunity against duplicate event log claims across different blocks or identical slots (tested in Attacks 9, 13, and 18).

---

## ADR-006: Consensus Update Pipeline State Authentication (P0)

### Context & Problem Statement
In pure off-chain verification functions (`handle_begin_update`, `handle_miller_update`, `handle_finish_update`), caller-supplied structs are validated internally for cryptographic invariants. However, an adversarial host or RPC relayer could fabricate uncommitted in-memory `InstanceAccount` or `JobAccount` states to spoof light-client progression or bypass committee handoffs.

### Decision
Mosoo implements authenticated persistent transaction entrypoints:
- `handle_begin_update_authenticated(store, instance_pda, args)`
- `handle_miller_update_authenticated(store, instance_pda, job_pda, args)`
- `handle_finish_update_authenticated(store, instance_pda, job_pda, args)`

Each entrypoint strictly enforces:
1. **Program Ownership**: `store.get_account_owner(pda) == Some(MOSOO_PROGRAM_ID)`.
2. **Canonical PDA Derivation**: Recomputed SHA-256 PDA address matches the storage address.
3. **State Invariants**: Monotonically advancing slots, authentic bootstrap checkpoints, and valid stage sequencing.
4. **Atomic Batch Commit**: Updates to `InstanceAccount`, `HeaderRecord`, and `JobAccount` are committed atomically via `try_set_accounts_batch_with_owner`.

---

## ADR-007: Sepolia Glamsterdam / Gloas Hard Fork Alignment (P1)

### Context & Problem Statement
Sepolia activated the Glamsterdam / Gloas upgrade on October 6, 2026. Preliminary testing used an arbitrary test slot `7,077,888`. Using a misaligned fork boundary causes BLS signing domain divergence and consensus update rejection.

### Decision
Aligned `SEPOLIA_GLOAS_FORK_SLOT` with the official Ethereum Foundation Glamsterdam activation slot:
- Activation Slot: **`11,296,768`** (Epoch `353,024`, Oct 6, 2026)
- Fork Version: `[0x90, 0x00, 0x00, 0x77]`
- Generalized Indices: GINDEX 2945 (current sync committee), 2946 (next sync committee), 735 (finalized root), 2856 (execution block hash).
- Hoodi Testnet: Postponed on Oct 22, 2026; unscheduled Gloas boundary, remaining on Fulu until official replacement schedule is published.

---

## ADR-008: Dynamic `NetworkConfig` Propagation (P1)

### Context & Problem Statement
Logos RFP-021 mandates support for "any Ethereum-consensus chain without code modification." While `NetworkConfig` was defined in `types.rs`, BLS domain derivation previously fell back solely to hardcoded chain IDs.

### Decision
`compute_sync_committee_domain_with_config`, `compute_signing_root_with_config`, and `verify_sync_committee_signature_with_config` dynamically consume `Option<&NetworkConfig>`:
- If provided and non-zero, `config.genesis_validators_root` and custom fork versions directly override defaults.
- Backward-compatible standard entrypoints delegate with `None`.

---

## ADR-009: Historical Attestation Window (8,192-Slot Ring Buffer) (P2)

### Context & Problem Statement
Ethereum's consensus `BeaconState` maintains `block_roots: Vector[Root, 8192]`. Historical block headers older than 8,192 slots ($\approx 27.3$ hours) wrap around the circular ring buffer and cannot be proven solely from the active beacon state root.

### Decision
Mosoo enforces a strict fail-closed boundary:
1. Proofs for blocks within the 8,192-slot window ($0 < \text{current\_slot} - \text{header\_slot} \le 8192$) are verified against `state_root.block_roots` using depth-13 Merkle branches.
2. Requests for blocks older than 8,192 slots return a typed `MosooError::HistoricalSummariesWindowExceeded` error, preventing false attestations from overwritten ring buffer slots.

