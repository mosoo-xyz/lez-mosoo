# Mosoo Architectural Decision Records (ADRs)

This document formalizes the key architectural decisions, threat models, design rationales, and consensus invariants underpinning the **Mosoo** trustless Ethereum state attestation bridge for Logos Execution Zone (LEZ), developed in accordance with **Logos RFP-021**.

---

## Table of Contents
- [ADR-001: 3-Transaction Pipeline with Cryptographic Intermediate Commitments](#adr-001-3-transaction-pipeline-with-cryptographic-intermediate-commitments)
- [ADR-002: Strict Altair Light Client Committee Period Selection & Dynamic Handoff](#adr-002-strict-altair-light-client-committee-period-selection--dynamic-handoff)
- [ADR-003: Cryptographic RLP Block Header Root Derivation for Gloas ePBS](#adr-003-cryptographic-rlp-block-header-root-derivation-for-gloas-epbs)
- [ADR-004: Instance Immutability & Re-anchoring via Fresh Instance Initialization](#adr-004-instance-immutability--re-anchoring-via-fresh-instance-initialization)
- [ADR-005: Dual-Nullifier Architecture for Two-Way Bridge Double-Spend Immunity](#adr-005-dual-nullifier-architecture-for-two-way-bridge-double-spend-immunity)
- [ADR-006: Atomic Same-Transaction Verification & AccountStore Provenance](#adr-006-atomic-same-transaction-verification--accountstore-provenance)
- [ADR-007: Sepolia Glamsterdam / Gloas Hard Fork Alignment (P1)](#adr-007-sepolia-glamsterdam--gloas-hard-fork-alignment-p1)
- [ADR-008: Dynamic NetworkConfig Propagation (P1)](#adr-008-dynamic-networkconfig-propagation-p1)
- [ADR-009: Historical Attestation Window (8,192-Slot Ring Buffer) (P2)](#adr-009-historical-attestation-window-8192-slot-ring-buffer-p2)
- [ADR-010: Statement Provenance, Cross-Instance Isolation, and Shielded Privacy](#adr-010-statement-provenance-cross-instance-isolation-and-shielded-privacy)

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

---

## ADR-010: Statement Provenance, Cross-Instance Isolation, and Shielded Privacy

### Context & Problem Statement
The external audit on October 26, 2026 identified 6 critical pre-deployment and integration vulnerabilities:
1. **P0 Guest Caller-Supplied State**: The zkVM guest entrypoint directly accepted caller-provided `InstanceAccount` and `HeaderRecord` without verifying that their addresses match expected on-chain persistent PDAs.
2. **P1 Consumer Claim APIs**: Public test harness methods (`mint_meth_atomic`, `claim_atomic_u256`) accepted arbitrary in-memory structs without verifying persistent storage or pinned bridge configurations.
3. **P1 Multi-Instance Isolation**: `VerifiedStatement` lacked source light-client identity (`source_instance_pda`, `genesis_validators_root`), allowing statements produced by unapproved instances to be accepted by consumers.
4. **P1 Privacy Leakage (RFP-021 Functionality #8)**: `StatementBinding` exposed plain-text Ethereum addresses, contract vaults, and LEZ recipients in public journals.
5. **P2 Legacy Solidity Routes**: Legacy withdrawal routes lacked `sourceInstance` EIP-712 domain separation.
6. **P2/P3 Statement ID Specification Inconsistency**: Documentation described statement IDs as hashing predicate JSON, whereas the canonical specification hashes underlying raw Ethereum facts.

### Decision & Implementation
1. **Authenticated zkVM Instructions (Finding 1)**:
   Added `GuestInstruction::AttestStateAuthenticated`, `FinishUpdateAuthenticated`, `BeginUpdateAuthenticated`, and `MillerUpdateAuthenticated` in `mosoo-core/src/verifier.rs` and dispatched via `methods/guest/src/main.rs`. Verifies `args.instance.pda_address() == expected_instance_pda` and `args.header.pda_address() == expected_header_pda` before executing state verification.
2. **Persistent Store-Backed Consumer Minting (Finding 2)**:
   Implemented `MethLedger::mint_deposit_authenticated_store_u256` and `Erc20Ledger::mint_deposit_authenticated_store_u256`. Pinned `TrustedBridgeConfig` strictly verifies persistent storage provenance before token issuance. Deprecated legacy test harnesses.
3. **Cross-Instance Isolation & V2 Statement ID (Finding 3)**:
   Added `genesis_validators_root: [u8; 32]`, `source_instance_id: [u8; 32]`, and `source_instance_pda: [u8; 32]` to `VerifiedStatement`.
   Implemented `derive_statement_id_v2`:
   $$\text{statement\_id} = \text{SHA-256}(\text{"mosoo\_statement\_v2"} \parallel \text{chain\_id} \parallel \text{gvr} \parallel \text{source\_instance\_pda} \parallel \text{subject\_key} \parallel \text{proof\_type} \parallel \text{verified\_value})$$
   Guarantees distinct statement nullifiers for identical state facts across independent light-client instances.
4. **Shielded Statement Binding (Finding 4)**:
   Added `StatementBinding::Shielded { commitment: [u8; 32] }` and `VerifiedStatement::shield(&self)`. Cryptographically hashes account and transaction metadata into a 32-byte commitment, eliminating all plain-text address leakage in the public journal.
5. **Solidity Legacy Route Governance (Finding 5)**:
   Added `legacyRoutesEnabled`, `disableLegacyRoutes()`, and `error LegacyRoutesDisabled()` to `contracts/MosooLocker.sol`. Legacy routes can be disabled while instance-bound V2 quorum routes remain active.
6. **Canonical Invariant Documentation (Finding 6)**:
   Corrected `VerifiedStatement` documentation to reflect that statement nullifiers represent raw verified Ethereum state facts, ensuring invariance across predicate variants ($AtLeast(10) \equiv AtLeast(50)$) to prevent nullifier bypass.

---

## ADR-011: Unified Checkpoint Validation, Atomic Storage Rollback, Strict ABI Event Typing, and Blinding Privacy Nullifiers

### Context & Problem Statement
An external re-audit of the codebase identified 5 critical and high-priority edge cases across storage persistence, dispatch routing, event matching, and privacy leakage:
1. **P0 Shared Checkpoint Verification Across Dispatchers (Finding 15)**: `dispatch_guest_instruction()` checked canonical checkpoints, but `dispatch_store_instruction()` (via `handle_initialize_store()`) did not execute the same checkpoint verification, creating a bypass risk if called via persistent storage adapters.
2. **P1 Immutable Instance Defense (Finding 16)**: `handle_initialize_store()` did not assert that the instance account was absent before writing, creating a risk where re-initialization with the same `(chain_id, instance_id)` could overwrite an existing instance account and reset consensus progress.
3. **P1 Batch-Write Rollback State Loss (Finding 17)**: `AccountStore::try_set_accounts_batch_with_owner()` recorded written addresses and removed them upon downstream batch failure. If an existing account (such as `InstanceAccount`) was overwritten in a batch that later failed, rollback deleted the account rather than restoring its pre-batch state and owner.
4. **P1 Strict Event Typing & Recipient Matching (Finding 18 & 19)**:
   - In `ProofTarget::Erc20Deposit`, `recipient` verification allowed ambiguous address fallback instead of strict 32-byte equality against the canonical `bytes32 indexed lezRecipient` topic.
   - In `ProofTarget::Erc20Transfer`, missing topic count verification (`topics.len() == 3`), data length verification (`data.len() == 32`), and address zero-padding verification allowed non-standard event shapes to be processed.
5. **P1 Statement Unlinkability & Privacy Blinding (Finding 20)**: `VerifiedStatement::shield()` only blinded the provenance binding. The deterministic `subject_key` and `statement_id` remained public, allowing observers with knowledge of public Ethereum events to correlate candidate keys against the public journal.

### Decision & Implementation
1. **Unified Initialization Validation (`validate_initialize`)**:
   Extracted canonical checkpoint validation into `validate_initialize(args: &InitializeArgs) -> Result<(), MosooError>`. Called uniformly in both `dispatch_guest_instruction()` and `handle_initialize_store()` (and `dispatch_store_instruction()`). Enforces that Mainnet, Sepolia, and Holesky match pinned checkpoints and custom networks declare non-zero `genesis_validators_root`.
2. **Create-Only Instance Storage Guard**:
   In `handle_initialize_store()`, added an atomic check:
   ```rust
   if store.has_account(&pda) {
       return Err(MosooError::AlreadyInitialized { chain_id: instance.chain_id });
   }
   ```
   Ensures light-client instances are strictly immutable once initialized.
3. **Snapshot-Restoring Batch Write Rollback**:
   Updated `AccountStore::try_set_accounts_batch_with_owner()` to capture pre-write `AccountSnapshot { address, data, owner }`. When any write in the batch fails, previous writes are rolled back in reverse order:
   - Existing accounts are restored to their pre-batch `data` and `owner`.
   - Newly created accounts (`data: None`) are removed.
   - Any secondary rollback failures are captured in `StoreError::BatchRollbackPartialFailure`.
4. **Strict ABI Event Shape & Exact Recipient Equality**:
   - `Erc20Deposit`: Strictly checks `verified_log.topics[3].0 == *recipient` (exact 32 bytes) and returns `MosooError::RecipientMismatch`.
   - `Erc20Transfer`: Strictly requires `topics.len() == 3`, `data.len() == 32`, 12 leading zero bytes on address topics, and rejects malformed lengths.
5. **Blinding Subject Keys & Statement Nullifiers (`shield_with_salt`)**:
   Updated `VerifiedStatement::shield_with_salt(salt)` to blind both `subject_key` and `statement_id`:
   $$\text{salted\_subject\_key} = \text{SHA-256}(\text{"mosoo\_salted\_subject\_key\_v1:"} \parallel \text{salt} \parallel \text{subject\_key})$$
   $$\text{salted\_statement\_id} = \text{SHA-256}(\text{"mosoo\_salted\_statement\_id\_v1:"} \parallel \text{salt} \parallel \text{statement\_id})$$
   Provided `verify_salted_blinding()` for consumers holding the blinding salt to authenticate the statement and replay nullifier privately.
   Documented the privacy nullifier trade-off: public deterministic nullifiers prevent double-spend publicly at the expense of unlinkability against public Ethereum event observers; salted blinding provides zero-leakage unlinkability for private consumer redemption routes.


---

## ADR-012: Store-Backed Guest Entrypoint Authentication, Native ETH Exact Recipient Equality, Unowned Rollback Preservation, and Custom Checkpoint Trust Registration

### Context & Problem Statement
A follow-up independent audit (Session 5 - Oct 26, 2026) identified 5 specific findings across guest execution persistence, native ETH deposit event matching, custom network trust verification, statement unlinkability, and rollback edge cases:
1. **Critical #1 (P0) Actual Guest Entrypoint Persistent Account Authentication**:
   `methods/guest/src/main.rs` directly called `dispatch_guest_instruction(instruction)`. While `dispatch_store_instruction` existed for LEZ runtime environments, the guest entrypoint lacked a persistent store-backed instruction envelope. `AttestStateAuthenticated` only asserted `args.instance.pda_address() == expected_instance_pda`. Because PDA addresses only bind `(chain_id, instance_id)`, an adversary could supply an altered sync committee or modified consensus state under the canonical PDA without it being loaded from or authenticated by persistent storage accounts.
2. **High #2 (P1) Native ETH Deposit Recipient-Matching Ambiguity**:
   In `mosoo-core/src/inclusion.rs` (`ProofTarget::NativeEthDeposit`), canonical `DepositETH(address,bytes32,uint256,uint64)` and legacy `Deposit` events were accepted, but fallback matching allowed matching `recipient[0..20]` against a 20-byte topic even if the remaining 12 bytes differed (`to_topic.0[12..32] == recipient[0..20]`), leading to ambiguous recipient matching semantics.
3. **High #3 (P1) Custom Network Checkpoint Trust Anchor External Verification**:
   `validate_initialize()` verified canonical checkpoints for Mainnet, Sepolia, and Holesky, but custom networks lacked a requirement to bind their `trusted_checkpoint_root` to an externally authenticated anchor, allowing self-certified checkpoints to pass initialization without independent verification.
4. **High for Privacy Compliance #4 (P1) Default Public Statement Linkability**:
   `methods/guest/src/main.rs` called `stmt.shield()`, but unsalted `shield()` only replaced `binding` with its commitment; `subject_key` and `statement_id` remained linkable to public Ethereum events.
5. **Medium #5 (P2) Batch Rollback Unknown Owner Edge Case**:
   In `AccountStore::try_set_accounts_batch_with_owner()`, when restoring an existing account where `snap.owner` was `None` (unowned / unknown owner), the code fell back to `let orig_owner = snap.owner.unwrap_or(MOSOO_PROGRAM_ID)`. This incorrectly converted an unowned account into a program-owned account upon rollback.

### Decision & Implementation
1. **Store-Backed Guest Instruction Execution (`GuestInstruction::StoreBacked`)**:
   Added `GuestInstruction::StoreBacked { store: ProgramAccountStore, instruction: Box<GuestInstruction> }`. In `dispatch_guest_instruction`, `StoreBacked` dispatches directly to `dispatch_store_instruction(&mut store, *instruction)`. When an authenticated instruction is dispatched, the genuine `InstanceAccount` (and `HeaderRecord` / `JobAccount`) is loaded strictly from persistent storage accounts owned by `MOSOO_PROGRAM_ID`, overriding any caller-supplied fabricated committee or altered consensus state.
2. **Strict Exact 32-Byte Recipient Equality on Native ETH Deposits**:
   In `mosoo-core/src/inclusion.rs`:
   - For canonical `DepositETH(address,bytes32,uint256,uint64)` and `Deposit(address,bytes32,uint256)`: Enforced strict exact 32-byte equality (`to_topic.0 == *recipient`), returning `MosooError::RecipientMismatch` on mismatch.
   - For legacy `Deposit(address,address,uint256)`: Strictly required that the event topic has 12 leading zeros (`to_topic.0[0..12] == [0u8; 12]`), the recipient is canonically padded with 12 leading zeros (`recipient[0..12] == [0u8; 12]`), and matches all 32 bytes (`to_topic.0 == *recipient`). Completely eliminated ambiguous partial matching fallbacks (`recipient[0..20]`).
3. **Independent Trust Anchor Verification for Custom Networks**:
   - Extended `NetworkConfig` with `trusted_checkpoint_root: Option<[u8; 32]>`. In `validate_initialize()`, custom networks (`!is_supported_chain_id`) MUST provide an externally verified `trusted_checkpoint_root` in `network_config` that matches `args.trusted_checkpoint_root`; otherwise initialization fails closed with `MosooError::UnconfiguredTrustedCheckpoint` or `MosooError::UntrustedCheckpoint`.
   - Added `TrustedBridgeConfig::register_trusted_checkpoint_authorized` and `TrustedBridgeConfig::register_custom_network` to permit administrative registration of verified custom network trust anchors.
4. **Zero-Linkability Statement Shielding**:
   Updated `VerifiedStatement::shield()` to blind `subject_key` and `statement_id` nullifiers in addition to `binding`:
   - Made `shield()` idempotent when called on already shielded or salted statements.
   - Preserves salted blinding when `shield_with_salt(&salt)` is used for private consumer redemption.
5. **Safe Restoration of Unowned Accounts during Batch Rollback**:
   - Updated `AccountSnapshot.owner` handling: If `snap.owner` is `Some(owner)`, rollback calls `try_set_account_with_owner`. If `snap.owner` is `None`, rollback delegates to `try_restore_account_unowned`, which restores `owner: None` in `ProgramAccountStore` without assigning `MOSOO_PROGRAM_ID`.
   - Added `StoreError::RollbackRestorationFailed` to report restoration errors without corrupting account ownership.
