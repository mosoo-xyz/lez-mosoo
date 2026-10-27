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


---

## ADR-013: Host-Enforced Storage Isolation, Production Gating of Deprecated Claim APIs, Native ETH Canonical 12-Zero Sender Padding, and Shielded Statement Consumer Witness Verification

### Context & Problem Statement
An exhaustive review (Audit Session 6 - Oct 26, 2026) evaluated the full codebase against Logos RFP-021, identifying key architectural and edge-case requirements:
1. **Critical #1 & #2 (P0) In-Memory Store Injection and Caller-Controlled zkVM Storage**:
   In zkVM guest (`methods/guest/src/main.rs`), `GuestInstruction::StoreBacked` allowed callers to supply `ProgramAccountStore` over `env::read()`. An adversary could supply a fabricated in-memory store with forged accounts marked `owner = MOSOO_PROGRAM_ID`. Furthermore, `dispatch_store_instruction` recursively passed `&mut store` (from the enum), discarding the host runtime's persistent store. In direct `Authenticated` guest instruction branches, unpinned chains were permitted to execute if `args.instance.pda_address() == expected_instance_pda`.
2. **High #3 (P1) Deprecated Public Claim Helpers Lack Production Gating**:
   In `consumers/erc20-receiver/src/lib.rs` and `consumers/ether-receiver/src/lib.rs`, `claim_with_store_u256`, `claim_with_store_u128`, `claim_ether_with_store_u256`, and `claim_ether_with_store_u128` were left `pub` without `#[cfg(any(test, feature = "test-harness"))]`, allowing callers to supply raw `VerifiedStatement` structs with fabricated `attester_program_id`.
3. **Medium #5 (P2) Native ETH Deposit Missing Canonical 12-Zero Sender Topic Padding**:
   In `mosoo-core/src/inclusion.rs` (`ProofTarget::NativeEthDeposit`) and `decode_deposit_eth_log`, `from_topic` only compared the last 20 bytes against sender, without checking `from_topic.0[0..12] == [0u8; 12]`. Non-canonical ABI-encoded topics could be accepted.
4. **Correctness #6 (P1) Public Shielded Statement vs Consumer API Schema Compatibility**:
   When `stmt.shield()` or `stmt.shield_with_salt()` blinded `binding` into `StatementBinding::Shielded`, consumer claim functions pattern-matched only on raw unshielded bindings (`NativeEthDeposit`, `Erc20Deposit`, `Erc20Transfer`), causing shielded zkVM emissions to be rejected.

### Decision & Implementation
1. **Host-Enforced Storage Isolation and zkVM Production Gating**:
   - Gated `GuestInstruction::StoreBacked` in `dispatch_guest_instruction` behind `#[cfg(any(test, feature = "test-harness"))]`, failing closed in production builds with `MosooError::UnauthenticatedInstance`.
   - In `dispatch_store_instruction` (host runtime execution), updated `GuestInstruction::StoreBacked` to dispatch against the host runtime's persistent `store`, completely ignoring any caller-supplied store.
   - Enforced that all `*Authenticated` guest instruction variants require `TrustedBridgeConfig::canonical().get_trusted_instance(chain_id)` to be registered and match `expected_instance_pda`, failing closed with `MosooError::UntrustedSourceInstance` for unpinned or mismatched instances.
   - Enforced `instance.validate_authenticity()?` inside `verify_instance_account_authenticity()`.
2. **Production Gating of Deprecated Claim Helpers**:
   - Gated `claim_with_store_u256`, `claim_with_store_u128`, `claim_ether_with_store_u256`, and `claim_ether_with_store_u128` strictly behind `#[cfg(any(test, feature = "test-harness"))]`.
   - Production consumers must only use `claim_authenticated_pda_u256`, `claim_authenticated_runtime_account_u256`, `claim_authenticated_store_u256`, or `claim_shielded_statement_u256`.
3. **Canonical 12-Zero Sender & Token Topic Padding**:
   - In `mosoo-core/src/inclusion.rs`, enforced `topic.0[0..12] == [0u8; 12]` across `ProofTarget::NativeEthDeposit`, `decode_deposit_eth_log`, `ProofTarget::Erc20Deposit`, and `decode_deposit_erc20_log`.
4. **Privacy-Shielded Statement Consumer Witness Redemption**:
   - Added `ShieldedErc20ClaimWitness` and `claim_shielded_statement_u256` in `consumers/erc20-receiver/src/lib.rs`.
   - Added `ShieldedEtherClaimWitness` and `claim_shielded_ether_statement_u256` in `consumers/ether-receiver/src/lib.rs`.
   - Consumers verify the commitment and blinded identifiers against the claimant's private witness preimage (unshielded binding + optional salt), maintaining zero on-chain linkability while ensuring robust replay protection and parameter authenticity.

---

## ADR-014: Weak-Subjectivity Expiry Enforcement, RFP-021 Canonical Statement ID Derivation, and Persistent Account Dispatch Hardening

### Context & Problem Statement
External review (Audit Session 7 - Oct 26, 2026) evaluated the architecture and identified critical edge cases:
1. **Critical #1 (P0): Persistent Account Authentication & Dispatch Separation**:
   In zkVM guest (`methods/guest/src/main.rs`), instructions deserialize from `env::read()`. While in-memory `StoreBacked` is rejected in production builds (`UnauthenticatedInstance`), PDA derivation checks (`pda_address = sha256("mosoo_instance" || chain_id || instance_id)`) only bound chain and instance IDs, leaving internal consensus roots susceptible to prover forgery if not strictly validated against authentic storage or pinned anchors.
2. **High #2 (P1): Incomplete Weak-Subjectivity Expiry Enforcement in `handle_begin_update()`**:
   `handle_begin_update()` checked forward slot leaps (`finalized_header.slot <= current_slot + 1_728_000`), but did not prevent an adversary from advancing a stale/expired light client instance through small incremental updates (e.g. 50 slots). Under Ethereum PoS rules, light client sync committees cannot be trusted if an instance has stalled beyond the canonical weak-subjectivity window (~54,000 slots / ~18.75 days).
3. **Medium #3 (P2): Statement ID Cross-Instance Determinism (RFP-021 Functionality #6 vs #15)**:
   In `mosoo-core/src/predicate.rs`, `derive_statement_id_v2()` included `source_instance_pda` in the statement ID hash calculation. This caused two independent instances verifying the identical Ethereum state fact to emit different statement IDs, conflicting with RFP-021 Functionality #6 ("For identical verified Ethereum state, the emitted statement identifier MUST be identical and deterministic").
4. **Solidity Bridge Asymmetric Trust Model & Governance Clarity**:
   Evaluated `contracts/MosooLocker.sol`: clarified the dual trust model (trustless consensus verification for ETH-to-LEZ inbound, witness-attested quorum verification for LEZ-to-ETH outbound settlement).

### Decision & Implementation
1. **Persistent Account Authentication & Dispatch Separation**:
   - Clarified and enforced the architectural distinction between LEZ runtime transaction dispatch (`dispatch_store_instruction(&mut host_store, instruction)` with genuine RocksDB/state trie storage) and zkVM guest proof verification.
   - Enhanced `InstanceAccount::validate_authenticity_strict()` to strictly assert that `bootstrap_header_hash` matches canonical pinned checkpoint anchors and `pda_address()` matches canonical pinned instance addresses.
   - Updated `methods/guest/src/main.rs` documentation and dispatch paths to strictly enforce authenticated witnesses.
2. **Weak-Subjectivity Expiry Enforcement**:
   - Introduced `CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 54_000` (≈ 18.75 days) and `MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 1_728_000` (~240 days).
   - In `BeginUpdateArgs`, added `trusted_head_slot: Option<u64>` to anchor updates against current Ethereum head time.
   - In `handle_begin_update()`, if `trusted_head_slot` indicates the instance has stalled past 54,000 slots, or if an update jumps > 54,000 slots, the update fails closed with `MosooError::WeakSubjectivityExpired`. Chained small updates on expired instances are strictly rejected.
   - In `handle_attest_state()`, attested states against instances stalled beyond `CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS` fail closed with `MosooError::WeakSubjectivityExpired`.
3. **Canonical State Fact Statement ID Derivation**:
   - Updated `derive_statement_id_v2(chain_id, genesis_validators_root, subject_key, proof_type_tag, verified_value)` to derive statement IDs strictly from canonical Ethereum state facts.
   - Cross-instance determinism is guaranteed per RFP-021 Functionality #6.
   - Light-client instance binding is preserved in `VerifiedStatement.source_instance_pda` and strictly enforced at consumer boundaries per RFP-021 Functionality #15.
4. **Bridge Governance & Deployment Criteria Documentation**:
   - Explicitly documented the witness-attested quorum model, emergency timelocks, daily limits, and production exit criteria in project security specifications.

---

## ADR-015: Production Persistent Store Dispatch, Unified PDA Derivation, Weak-Subjectivity Direction Correction, and Irreversible Legacy Route Retirement
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 8 static code review raised five critical and high-priority concerns:
1. **Critical #1 (P0): Persistent Account Authentication in Production Dispatch**:
   `GuestInstruction::StoreBacked` was gated behind `cfg(test)`, returning `UnauthenticatedInstance` in production. Authenticated instruction variants (`AttestStateAuthenticated`, etc.) compared PDA address without validating that the internal consensus roots, committee, or execution state roots belonged to an authentic persistent account.
2. **High #2 (P1): Weak-Subjectivity Freshness Guard Bypass & Inverted Calculation Bug**:
   - In `BeginUpdateArgs`, `trusted_head_slot` was optional defaulting to `None`, bypassing freshness checks if omitted.
   - In `handle_attest_state()`, `args.instance.is_stale_canonical(args.header.slot)` suffered an inverted subtraction bug: because `header.slot <= instance.current_slot` is enforced, `args.header.slot.saturating_sub(instance.current_slot)` evaluated to 0, rendering staleness checks a no-op.
3. **High #3 (P1): Canonical Network Constants & PDA Derivation Inconsistency**:
   - `derive_instance_pda()` included `MOSOO_PROGRAM_ID` in the hash, while `InstanceAccount::pda_address()` omitted it.
   - `CANONICAL_SEPOLIA_MOSOO_INSTANCE` was derived without program ID, while Mainnet and Holesky were derived with program ID.
   - `CANONICAL_MAINNET_CHECKPOINT_ROOT` (`0xaabbccd...`) and Holesky (`0x578b9...112233...`) were dummy placeholder patterns advertised in `TrustedBridgeConfig::canonical()`.
4. **Medium #4 (P2): Legacy Withdrawal Routes Irreversible Disable**:
   In `MosooLocker.sol`, `legacyRoutesEnabled` could be re-enabled at any time by the owner via `setLegacyRoutesEnabled(true)`. A permanent retirement mechanism was missing.
5. **Medium #5 (P2): Initial Attester Quorum Policy**:
   Documented multi-signer quorum enforcement on Mainnet deployment day-one to mitigate the 1-of-1 initial default constructor configuration.

### Decision & Implementation
1. **Production Persistent Account Dispatch (P0)**:
   - Enabled `GuestInstruction::StoreBacked` unconditionally across test and production builds.
   - In production, caller-provided un-backed state accounts without an authentic persistent `AccountStore` are rejected fail-closed with `MosooError::UnauthenticatedInstance`. Production execution strictly uses `dispatch_store_instruction`, loading accounts with `owner == MOSOO_PROGRAM_ID` and replacing caller-supplied instance and header state with verified on-chain state.
   - Added explicit negative regression test (`test_session8_finding1_fabricated_committee_and_execution_roots_under_canonical_pda_fails_closed`) verifying that fabricated committee and execution roots under a canonical instance ID are strictly rejected.
2. **Weak-Subjectivity Freshness Direction & Mandatory Head Validation (P1)**:
   - In `handle_begin_update()`, if `trusted_head_slot` is omitted, fallback to checking `update.signature_slot` freshness. The effective head slot is asserted to not precede `instance.current_slot`, and staleness past 54,000 slots fails closed.
   - In `handle_attest_state()`, historical freshness is corrected to: `instance.current_slot.saturating_sub(header.slot) > CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS` fails closed. If `trusted_head_slot` is supplied, `trusted_head_slot < instance.current_slot` and `is_stale_canonical(trusted_head_slot)` are strictly enforced.
3. **Unified PDA Derivation & Canonical Constants Alignment (P1)**:
   - Unified `InstanceAccount::pda_address(&self)` to delegate directly to `derive_instance_pda(self.chain_id, &self.instance_id)`.
   - Updated `CANONICAL_SEPOLIA_MOSOO_INSTANCE` to the canonical program-ID-inclusive derivation: `[0x98, 0x4a, 0x6b, 0x2e, 0x81, 0xc3, 0x18, 0x49, 0x2c, 0x2c, 0x0a, 0xbd, 0x21, 0x1d, 0xfb, 0xbb, 0x64, 0x1a, 0x3e, 0x71, 0xa5, 0xb2, 0x7f, 0xcf, 0x80, 0x67, 0x32, 0xad, 0x55, 0x86, 0x19, 0x12]`.
   - Cleaned `TrustedBridgeConfig::canonical()` to pre-register only Sepolia (the live network with verified checkpoint). Mainnet and Holesky require explicit authorized checkpoint registration prior to activation.
   - Added automated invariant test (`test_session8_finding3_pda_derivation_invariants_across_all_networks`) asserting `derive_instance_pda(chain_id, &instance_id) == expected_instance_pda == instance.pda_address()` across all networks.
4. **Irreversible Permanent Retirement of Legacy Withdrawal Routes (P2)**:
   - Added `bool public legacyRoutesPermanentlyDisabled;`, `error LegacyRoutesArePermanentlyRetired();`, and `event LegacyRoutesPermanentlyRetired();` in `MosooLocker.sol`.
   - Added `permanentlyRetireLegacyRoutes()` external function (owner only).
   - `setLegacyRoutesEnabled(true)` strictly reverts with `LegacyRoutesArePermanentlyRetired()` if permanently retired.
   - Added Foundry unit test verifying permanent retirement.
5. **Outbound Multi-Signer Quorum Operational Policy (P2)**:
   - Documented mandatory multi-signer committee setup prior to mainnet deposit acceptance, ensuring quorum thresholds (`requiredQuorum >= 2/3`) and independent guardian controls are active from genesis.

---

## ADR-016: Unified Job PDA Derivation, Store-Backed Guest Isolation, Independent Checkpoint Authorization, and Stale Instance Update Shielding
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 9 code review identified five critical and security-relevant vulnerabilities and configuration risks:
1. **Critical #1 (P0): `StoreBacked` Untrusted Serialized Storage in zkVM Guest Entrypoint**:
   `GuestInstruction::StoreBacked` received `ProgramAccountStore` directly inside the instruction envelope deserialized from `env::read()`. Because `ProgramAccountStore` and `ProgramAccount` are serializable, an untrusted prover could construct an in-memory store with `owner: MOSOO_PROGRAM_ID`, fabricated headers, and forged execution roots, bypassing LEZ blockchain storage backing.
2. **High #2 (P1): Weak-Subjectivity Freshness Dependency on Caller Input**:
   In `BeginUpdateArgs`, `trusted_head_slot` was optional (`None`), falling back to `update.signature_slot`. Attestation handlers only verified freshness if `trusted_head_slot` was present. An adversary could attempt to keep an expired instance usable through small chained incremental updates or bypass freshness checks by passing `None`.
3. **High #3 (P1): Custom `NetworkConfig` Self-Certifying Checkpoint Trust Anchor**:
   In `validate_initialize()`, for unconfigured networks, caller-supplied `NetworkConfig.trusted_checkpoint_root` was compared against caller-supplied `args.trusted_checkpoint_root`. Both came from caller input, allowing unanchored networks to self-certify.
4. **Medium #4 (P2): Job PDA Derivation Formula Inconsistency**:
   `JobAccount` exhibited three diverging derivation formulas:
   - `pda_address()` hashed `b"mosoo_job" || chain_id || instance_id || nonce` (omitted `MOSOO_PROGRAM_ID`).
   - `instance_pda()` hashed `b"mosoo_instance" || chain_id || instance_id` (omitted `MOSOO_PROGRAM_ID`).
   - `derive_pda(instance_pda, nonce)` hashed `b"mosoo_job" || instance_pda || nonce`.
5. **Medium #5 (P2): Mainnet and Holesky Placeholder Constants Removal**:
   Placeholder constants (`CANONICAL_MAINNET_CHECKPOINT_ROOT = [0xaa, 0xbb, ...]`, `CANONICAL_HOLESKY_CHECKPOINT_ROOT = [0x57, 0x8b, ...11223344...]`, dummy lockers `0x10500...1`, `0x17000...1`) remained in source code, carrying the risk of accidental production trust assumptions.

### Decision & Implementation
1. **zkVM Guest Store-Backed Isolation (P0)**:
   - Gated `GuestInstruction::StoreBacked` behind `#[cfg(any(test, feature = "test-harness"))]` in `dispatch_guest_instruction`. In production zkVM guest builds, caller-supplied serialized `ProgramAccountStore` instructions are strictly rejected fail-closed with `MosooError::UnauthenticatedInstance`.
   - In LEZ runtime, host executions strictly call `dispatch_store_instruction(&mut host_store, instruction)` with genuine RocksDB/host-owned accounts, never accepting caller-provided serialized stores.
   - Added adversarial test (`test_session9_finding1_adversarial_forged_store_fails_closed`) asserting that fabricated stores with forged accounts and fake headers fail closed.
2. **Authenticated Freshness Anchor & Incremental Update Shielding (P1)**:
   - Added `trusted_heads: HashMap<u64, u64>` and administrative registration methods (`register_trusted_head`, `register_trusted_head_authorized`, `get_trusted_head`) to `TrustedBridgeConfig`.
   - In `handle_begin_update_authenticated` and `handle_attest_state_authenticated`, instances must not be stale relative to the authenticated network head (`anchor_head`). Caller attempts to provide fake low heads or pass `None` cannot bypass the authenticated anchor.
   - Added automated test (`test_session9_finding2_stale_instance_cannot_advance_via_small_incremental_updates`) proving that an expired instance cannot be revived or kept alive via chained small incremental updates (e.g. 100-slot jumps).
3. **Independent Checkpoint Authorization Enforcement (P1)**:
   - Updated `validate_initialize_with_config` and `validate_initialize` so that checkpoint trust roots MUST be independently registered in `TrustedBridgeConfig`. Caller-supplied `NetworkConfig` is never self-certifying. Unregistered networks fail closed with `UnconfiguredTrustedCheckpoint`.
   - Added regression test (`test_session9_finding3_and_5_unregistered_networks_fail_closed_without_config_registration`) verifying that unconfigured networks (Mainnet, Holesky, custom chains) fail closed without independent authorization.
4. **Unified Canonical JobAccount PDA Derivation (P2)**:
   - Unified `JobAccount::instance_pda(&self)` to delegate directly to `derive_instance_pda(self.instance_chain_id, &self.instance_id)` (incorporating `MOSOO_PROGRAM_ID`).
   - Unified `JobAccount::pda_address(&self)` to delegate directly to `Self::derive_pda(&self.instance_pda(), self.nonce)`.
   - Standardized `verify_job_account_authenticity` to check `job.pda_address() == *expected_pda`.
   - Added invariant unit test (`test_session9_finding4_job_pda_derivation_unification`) across multiple networks and nonces.
5. **Elimination of Placeholder Constants (P2)**:
   - Completely deleted placeholder constants `CANONICAL_MAINNET_CHECKPOINT_ROOT`, `CANONICAL_MAINNET_MOSOO_LOCKER`, `CANONICAL_HOLESKY_CHECKPOINT_ROOT`, and `CANONICAL_HOLESKY_MOSOO_LOCKER` from `mosoo-core/src/types.rs`.
   - Added test asserting that canonical configuration contains zero placeholder checkpoints for Mainnet and Holesky.

---

## ADR-017: Production Runtime Adapter, Strict Weak-Subjectivity Bootstrap, Core Instance Pinning, and Salted Privacy Blinding
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 10 code review identified five security findings and production integration blockers:
1. **High #1 (P1): Stale Ethereum Light-Client State & Strict Weak-Subjectivity Enforcement**:
   - `TrustedBridgeConfig::canonical()` initialized `trusted_heads` to an empty map.
   - `handle_begin_update_authenticated()` only enforced freshness if `config` contained a trusted head for that chain.
   - `handle_attest_state_authenticated()` fell back to `args.instance.current_slot` when no trusted head was configured (`(None, None) => args.instance.current_slot`), causing `current_slot.saturating_sub(current_slot) == 0` and disabling staleness protection entirely.
   - Initialization (`handle_initialize`) used `1_728_000` slots (~240 days) instead of the canonical operational weak-subjectivity threshold `54_000` slots (~7.5 days).
2. **High #2 (P1): Production Dispatcher & LEZ Runtime Integration**:
   - In `dispatch_guest_instruction()`, authenticated instruction variants (`BeginUpdateAuthenticated`, `MillerUpdateAuthenticated`, `FinishUpdateAuthenticated`, `AttestStateAuthenticated`) had unconditional `#[cfg(not(any(test, feature = "test-harness")))] return Err(MosooError::UnauthenticatedInstance);`, blocking genuine release zkVM executions.
   - A dedicated native LEZ runtime adapter was needed to connect SPEL transactions directly to `dispatch_store_instruction(&mut host_store, instruction)` with genuine persistent accounts.
3. **Medium #3 (P2): Instance Pinning in Core Account Loader**:
   - `verify_instance_account_authenticity()` validated internal invariants, but did not enforce that `instance.pda_address()` matches `TrustedBridgeConfig::get_trusted_instance(chain_id)`.
4. **Medium #4 (P2): Privacy Shielding Deterministic Hashing**:
   - `stmt.shield()` performed unsalted hashing if `privacy_salt` was omitted, allowing correlation of repeated statements and dictionary matching for known Ethereum addresses.
5. **Low #5 (P3): Timing Documentation & CI Dependency Audit Alignment**:
   - 54,000 slots was documented as "~18.75 days" instead of the exact 7.5 days on Ethereum PoS (12s per slot: 54,000 * 12s = 648,000s = 7.5 days).
   - CI workflow lacked dedicated dependency vulnerability audits.

### Decision & Implementation
1. **Strict Weak-Subjectivity Freshness & Automatic Consensus Advancement (P1)**:
   - Configured canonical Sepolia head (`ETH_SEPOLIA_CHAIN_ID -> CANONICAL_SEPOLIA_CHECKPOINT_SLOT`) in `TrustedBridgeConfig::canonical()`.
   - In `handle_begin_update_authenticated` and `handle_attest_state_authenticated`, strictly resolve `(args.trusted_head_slot, anchor_head)`: if neither is configured, execution fails closed immediately (`MosooError::InvalidBootstrap`).
   - In `handle_finish_update_authenticated`, automatically advance `config.register_trusted_head(updated_instance.chain_id, updated_instance.current_slot)` and persist it atomically into persistent storage, ensuring on-chain head progression.
   - In `handle_initialize` and `validate_initialize_with_config`, enforced `CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS` (54,000 slots / 7.5 days) so stale bootstrap checkpoints are rejected fail-closed.
2. **Production LEZ Runtime Adapter & zkVM Authenticated Dispatch (P1)**:
   - Implemented `LezRuntimeAdapter<S: AccountStore>` in `mosoo-core/src/verifier.rs`, providing native transaction dispatch (`dispatch_transaction`, `dispatch_begin_update`, `dispatch_miller_update`, `dispatch_finish_update`, `dispatch_attest_state`) against persistent storage.
   - Unlocked `*Authenticated` instruction execution in `dispatch_guest_instruction` for release builds, verifying cryptographic witnesses (pinned instance PDA, valid committees, authentic header provenance) without depending on `test-harness`.
3. **Core Loader Instance Pinning (P2)**:
   - In `verify_instance_account_authenticity`, load `TrustedBridgeConfig` and assert `*expected_pda == pinned` for any configured chain, returning `MosooError::UntrustedSourceInstance` on mismatch.
4. **Salted Privacy Shielding (P2)**:
   - Supported secret 256-bit salt in `AttestStateArgs` (`privacy_salt`), blinding `subject_key` and `statement_id` via `shield_with_salt()`.
   - In `methods/guest/src/main.rs`, preserved pre-shielded salted statements in the zkVM journal, keeping secret salts strictly within the private witness.
5. **Documentation & CI Alignment (P3)**:
   - Corrected all weak-subjectivity documentation across `types.rs`, `verifier.rs`, and ADRs to reflect exact 7.5 days (54,000 slots * 12s).
   - Added `rustsec/audit-check` step in `.github/workflows/ci.yml`.

---

## ADR-018: Production zkVM Trust Boundary, Universal Strict Configuration Loading, Freshness Anchor Verification, and Value Confidentiality Commitments
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 11 (`t_6ae08a7e61308191964e5c12f3b83e26`) conducted a comprehensive static security review of the full repository architecture, identifying several trust-boundary gaps and configuration risks:
1. **Critical #1 (P0): Production zkVM Guest Trust Boundary**:
   - While unauthenticated variants (`AttestState`, `BeginUpdate`, etc.) were gated in release builds, `dispatch_guest_instruction()` retained direct handlers for `*Authenticated` variants taking caller-supplied structs from `env::read()`.
   - PDA address checks alone do not verify that internal consensus state (sync committee pubkeys, execution state roots, finalized beacon roots) matches persistent on-chain state.
2. **High #2 (P1): Permissive Fallback via `load_or_canonical()`**:
   - Despite `TrustedBridgeConfig::load_strict()` being implemented, core handlers (`handle_begin_update_authenticated`, `handle_finish_update_authenticated`, `handle_attest_state_authenticated`, `handle_initialize_store`) continued calling `load_or_canonical(store)`.
   - On missing, unowned, or malformed configuration accounts, `load_or_canonical()` silently fell back to hardcoded canonical defaults, bypassing custom trust policies.
3. **High #3 (P1): Weak-Subjectivity Freshness Trust Model**:
   - If a chain lacked a configured trusted head, callers could supply arbitrary unauthenticated slots (`(Some(s), None) => s`).
   - Callers could also supply an older slot than the canonical anchor or an unverified inflated slot.
4. **Medium #4 (P2): Raw Verified Value Exposed Despite Privacy Shielding**:
   - `VerifiedStatement::shield()` and `shield_with_salt()` blinded binding provenance and subject keys, but left `verified_value` in the clear.
   - Applications requiring amount confidentiality leaked sensitive values to observers of the public zkVM journal.
5. **Medium #5 (P2): Non-Blocking Dependency Audit in CI & Documentation Desynchronization**:
   - `.github/workflows/ci.yml` ran `rustsec/audit-check` with `continue-on-error: true`.
   - Test counts in README and CI comments diverged from actual test suite metrics.
6. **Low #6 (P3): Solidity Locker Default Trust Model**:
   - `MosooLocker.sol` constructor allowed `guardian == address(0)` (silently defaulting to `msg.sender`/owner).

### Decision & Implementation
1. **Production zkVM Guest Trust Boundary & Runtime Adapter Routing (P0)**:
   - In `dispatch_guest_instruction()`, gated all caller-supplied `*Authenticated` variants behind `#[cfg(any(test, feature = "test-harness"))]`. In production zkVM guest builds (`#[cfg(not(any(test, feature = "test-harness")))]`), bare caller-supplied state instructions strictly return `Err(MosooError::UnauthenticatedInstance)`.
   - Production smart contract transactions on LEZ execute natively in the LEZ host runtime via `LezRuntimeAdapter<S>` or `dispatch_store_instruction(&mut host_store, instruction)`, where accounts are loaded strictly from authentic RocksDB persistent storage owned by `MOSOO_PROGRAM_ID`.
2. **Universal Strict Configuration Loading (P1)**:
   - Replaced `load_or_canonical()` across all consensus and attestation handlers with `TrustedBridgeConfig::load_strict(store)?`.
   - Missing, unowned, or corrupted config accounts immediately fail closed with `MosooError::ConfigError(...)`.
   - Added `ConfigError(#[from] ConfigError)` to `MosooError`.
3. **Rigorous Weak-Subjectivity Freshness Verification (P1)**:
   - Required an authenticated anchor head in `TrustedBridgeConfig` for the chain; missing anchor fails closed with `MosooError::InvalidBootstrap`.
   - If caller supplies `args.trusted_head_slot = Some(s)`:
     - `s < anchor_head` is rejected fail-closed (`MosooError::InvalidBootstrap`).
     - `s < args.instance.current_slot` is rejected fail-closed (`MosooError::InvalidBootstrap`).
     - `s > anchor_head + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS` (fake larger head attack) is rejected fail-closed (`MosooError::InvalidBootstrap`).
     - Effective head is securely resolved as `s.max(anchor_head)`.
   - If caller omits `trusted_head_slot`, effective head is `anchor_head.max(args.instance.current_slot)`.
   - Stale instances exceeding 54,000 slots fail closed with `MosooError::WeakSubjectivityExpired`.
4. **Value Confidentiality Commitments & Dual Privacy Modes (P2)**:
   - Extended `StatementBinding` with `StatementBinding::Confidential { commitment: [u8; 32], value_commitment: [u8; 32] }`.
   - Implemented `VerifiedStatement::shield_confidential(&self, salt: &[u8; 32]) -> Self`, computing a secret 256-bit salt commitment `Sha256(b"mosoo_salted_value_commitment_v1:" || salt || verified_value)` for `verified_value`.
   - Implemented `VerifiedStatement::verify_salted_value_commitment` for authorized commitment opening.
   - Formally separated **Address Privacy Mode** (for settlement bridges like ERC20/Ether receiver where `verified_value` must be read by the contract to release funds) and **Confidential Mode** (where both identity and value are committed).
5. **Blocking CI Security Audit & Test Count Synchronization (P2)**:
   - Removed `continue-on-error: true` from `rustsec/audit-check@v1` in `.github/workflows/ci.yml`.
   - Updated test count labels across `README.md` and `.github/workflows/ci.yml`.
6. **MosooLocker Guardian Independence (P3)**:
   - Enforced `if (_guardian == address(0)) revert InvalidGuardian();` and `if (_guardian == msg.sender) revert GuardianMustNotBeOwner();` in `MosooLocker.sol` constructor.

---

## ADR-019: Canonical Instance Pinning, Independent Freshness Anchor Verification, Deposit Proof Locker & Allowlist Attestation Guards, LEZ Runtime Adapter End-to-End Acceptance, and Default-Deny Privacy Shielding
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 12 (`t_6ae0a89707d88191b1048c4ae7d7770f`) reviewed the latest repository hardening and identified 5 key areas for complete production readiness:
1. **Finding 1 (High): Unpinned Instance Global Trusted Head Advancement**:
   - While `validate_initialize_with_config` pinned instances, update steps (`handle_begin_update_authenticated`, `handle_miller_update_authenticated`, `handle_finish_update_authenticated`) and config trusted head tracking permitted unpinned instances on supported chains to advance global `config.trusted_heads`.
   - In addition, per-instance trusted heads were not tracked separately from chain-wide heads in `TrustedBridgeConfig`.
2. **Finding 2 (High): Independent Weak-Subjectivity Freshness Verification**:
   - `validate_initialize_with_config` required an authenticated anchor head check for supported chains, ensuring caller-supplied heads preceding anchor head (`s < anchor`) or leaping beyond 54,000 slots (`s > anchor + 54_000`) are rejected fail-closed.
   - Operational freshness must enforce 54,000 slots (~7.5 days) against anchor head.
3. **Finding 3 (High): Deposit Proof Binding to Canonical Locker and Token Allowlist**:
   - `handle_attest_state_authenticated` and `handle_attest_state` did not validate `deposit_contract` and `token_contract` against `TrustedBridgeConfig` allowlists, permitting claims against arbitrary contracts.
4. **Finding 4 (Production Blocker): Real LEZ Runtime Integration & E2E Acceptance Test**:
   - Clarified that LEZ smart contracts execute natively on the host via `LezRuntimeAdapter<S>` and `dispatch_store_instruction` against persistent storage.
   - Required a full end-to-end acceptance test: `test_session12_finding4_lez_runtime_adapter_full_persistent_lifecycle_e2e` proving initialize -> 3-Tx update pipeline -> state attestation runs against persistent storage.
5. **Finding 5 (Medium): Default-Deny Privacy Shielding & Value Confidentiality**:
   - Added `PrivacyMode { Public, AddressPrivate, Confidential }` in `mosoo-core/src/types.rs`.
   - In `methods/guest/src/main.rs`: enforced default-deny privacy: private statement types (`AccountBalance`, `StorageSlot`, `ReceiptLog`) in zkVM public journal require value confidentiality (`stmt.is_value_shielded()`), rejecting unshielded value leakage.
   - Contextually applied `shield_with_salt` for settlement proofs and `shield_confidential` for non-settlement proofs.

### Decision & Implementation
1. **Canonical Instance Pinning & Per-Instance Head Tracking (Finding 1)**:
   - Added `instance_trusted_heads: HashMap<String, u64>` to `TrustedBridgeConfig` using hex-encoded PDA strings for fail-safe JSON serialization.
   - Implemented `is_trusted_or_unpinned(&self, chain_id, instance_pda)`, `register_trusted_head_for_instance()`, and `get_instance_trusted_head()`.
   - Enforced `config.is_trusted_or_unpinned(chain_id, instance_pda)` across `handle_begin_update_authenticated`, `handle_miller_update_authenticated`, and `handle_finish_update_authenticated`.
   - In `handle_finish_update_authenticated`, updated both chain head and per-instance trusted head in persistent storage.
2. **Independent Weak-Subjectivity Freshness Verification (Finding 2)**:
   - Enforced in `validate_initialize_with_config` that for supported chains, an authenticated anchor head must be registered.
   - Caller-supplied `trusted_head_slot` cannot precede anchor head (`s < anchor_head`) or exceed anchor head by > 54,000 slots.
   - Rejected bootstrap checkpoints where `anchor_head > bootstrap_header.slot + 54_000` with `MosooError::WeakSubjectivityExpired`.
3. **Deposit Proof Canonical Locker & Token Allowlist Attestation Guards (Finding 3)**:
   - In `handle_attest_state_authenticated` and `handle_attest_state`, enforced that `ProofTarget::NativeEthDeposit` and `ProofTarget::Erc20Deposit` require `config.is_trusted_locker(chain_id, deposit_contract)`.
   - For `ProofTarget::Erc20Deposit`, enforced `config.is_token_allowed(chain_id, token_contract)`.
   - Non-compliant targets immediately fail closed with `MosooError::UntrustedDepositContract` and `MosooError::UntrustedTokenContract`.
4. **Real LEZ Runtime Integration & E2E Acceptance Test (Finding 4)**:
   - Documented and verified that LEZ smart contracts execute natively on the host via `LezRuntimeAdapter<S>` and `dispatch_store_instruction` against persistent storage.
   - Implemented `test_session12_finding4_lez_runtime_adapter_full_persistent_lifecycle_e2e` verifying the complete persistent lifecycle: initialization, update creation, and state attestation using genuine MPT inclusion proofs against persistent storage.
5. **Default-Deny Privacy Shielding & Value Confidentiality (Finding 5)**:
   - Added `PrivacyMode` enum (`Public`, `AddressPrivate`, `Confidential`) in `mosoo-core/src/types.rs`.
   - Enforced in `methods/guest/src/main.rs` that private statement types (`AccountBalance`, `StorageSlot`, `ReceiptLog`) require value confidentiality (`stmt.is_value_shielded()`) in the public zkVM journal, rejecting unshielded value leakage.
   - Verified that settlement proofs use `shield_with_salt` (Address Privacy) while non-settlement proofs use `shield_confidential` (Confidential Privacy).

---

## ADR-020: Per-Instance Trusted Head Isolation, Hoodi Deprecation & Holesky Alignment, Fail-Closed Confidential Privacy Mode, and Operational Checkpoint Recovery Governance
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 13 (`t_6ae0badadd2881918bb1eb5361ed685b`) identified 4 critical operational and architectural findings in the consensus verifier and daemon infrastructure:
1. **Finding 1 (High): Cross-Instance Trusted-Head Contamination**:
   - `register_trusted_head_for_instance()` was mutating both `self.instance_trusted_heads` AND global `self.trusted_heads[chain_id]`.
   - In multi-instance or unpinned environments, an advance in Instance A inflated the chain-wide anchor head, shifting the freshness baseline for Instance B and causing unintended DoS or weak-subjectivity isolation failure.
2. **Finding 2 (Medium): Daemon CLI Advertised Hoodi, But Core Verifier Rejects It**:
   - Daemon and CLI help strings advertised `560048 = Hoodi`. However, `mosoo_core::types::is_supported_chain_id` only supports Mainnet (`1`), Sepolia (`11155111`), and Holesky (`17000`).
   - Running the daemon or CLI with chain ID `560048` led to runtime panics or obscure verification errors.
3. **Finding 3 (Medium): Optional Privacy Mode Permitted Silent Unshielded Emission**:
   - `privacy_salt` was optional in `AttestStateArgs`. When omitted, statements were emitted unshielded even when callers desired confidential assertions.
4. **Finding 4 (Operational Gap): Checkpoint Recovery & Stalled Instance Governance**:
   - Lack of formalized operational guidance on recovering stalled light-client instances exceeding the 54,000-slot operational freshness bound, rotating trusted heads, and administering 2-step timelocks.

### Decision & Implementation
1. **Per-Instance Trusted Head Isolation (Finding 1)**:
   - Updated `register_trusted_head_for_instance` in `mosoo-core/src/types.rs` to ONLY update `self.instance_trusted_heads`, preventing any cross-instance contamination of `trusted_heads[chain_id]`.
   - Global `trusted_heads[chain_id]` is strictly reserved for network-wide anchor observations configured by governance.
   - Added `get_effective_instance_head(&self, chain_id, instance_pda)` to safely resolve the instance's effective head:
     ```rust
     self.get_instance_trusted_head(instance_pda)
         .or_else(|| self.get_trusted_head(chain_id))
     ```
   - In `handle_begin_update_authenticated` and `handle_attest_state_authenticated`, resolved the anchor head using this per-instance isolation pattern.
2. **Hoodi Deprecation & Holesky Alignment (Finding 2)**:
   - Deprecated Hoodi (chain ID `560048`). Aligned all CLI options, daemon CLI flags, and error messages to officially support Ethereum Holesky (chain ID `17000`), Sepolia (`11155111`), and Mainnet (`1`).
   - Added startup validation in `daemon/src/main.rs`:
     ```rust
     if !mosoo_core::types::is_supported_chain_id(cli.eth_chain_id) {
         anyhow::bail!(
             "Unsupported Ethereum chain ID {}. Mosoo supports Mainnet (1), Sepolia (11155111), and Holesky (17000).",
             cli.eth_chain_id
         );
     }
     ```
3. **Fail-Closed Confidential Privacy Mode (Finding 3)**:
   - Added first-class `pub privacy_mode: Option<PrivacyMode>` to `AttestStateArgs`.
   - Implemented Step 0 guard in `handle_attest_state`: when `privacy_mode` is `Some(PrivacyMode::Confidential)` or `Some(PrivacyMode::AddressPrivate)`, a secret 256-bit `privacy_salt` is strictly required. If omitted, execution immediately fails closed with `MosooError::InvalidBootstrap`.
4. **Comprehensive Operations & Governance Guide (Finding 4)**:
   - Created `docs/OPERATIONS.md` detailing trusted head provisioning, stalled instance retirement and fresh checkpoint replacement (ADR-004), 2-step timelock workflows (`GOVERNANCE_TIMELOCK_DELAY = 2 days`), Guardian veto procedures, and multi-network registration standards.

---

## ADR-021: Weak-Subjectivity Freshness Anchor Guard Against Dormant Stale Instances, Multi-Instance Coexistence Registry (RFP-021 #15), Mainnet/Holesky Canonical Checkpoint Registration, and Test Suite Harmonization
**Date**: October 27, 2026  
**Status**: Accepted & Implemented  

### Context & Problem Statement
Audit Session 14 (`t_6ae0db284f808191a7b4a6457cf84e54`) analyzed edge-case vulnerabilities and operational integration deliverables across the consensus light client:
1. **Issue A (High): Weak-Subjectivity Freshness Bypass via `trusted_head_slot: None` or Self-Referential Head**:
   - In `handle_begin_update_authenticated` and `handle_attest_state_authenticated`, when `trusted_head_slot` was `None` or defaulted to `instance.current_slot`, staleness checks evaluated `current_slot.saturating_sub(current_slot) == 0`.
   - A dormant instance stalled for 30+ days (e.g. 216,000 slots) was never detected as expired, allowing attackers to perform stale updates or attestations without fresh bootstrapping.
2. **Issue B (High): Multi-Instance Coexistence & Checkpoint Registry (Logos RFP-021 Functionality #15)**:
   - `TrustedBridgeConfig` previously stored single `trusted_instances: HashMap<u64, [u8; 32]>` and `trusted_checkpoints: HashMap<u64, [u8; 32]>` maps per chain ID.
   - RFP-021 Functionality #15 requires supporting multiple independent coexisting light-client instances and verified checkpoints on the same network without cross-contamination.
3. **Section 3 (Functional Gap): Mainnet and Holesky Canonical Constants & On-Chain Admin Registration**:
   - Mainnet (`10_320_000`) and Holesky (`3_250_000`) weak-subjectivity canonical checkpoint constants were missing.
   - An on-chain administrative instruction to register authorized checkpoints and multi-instance PDAs on the LEZ runtime without redeployment was needed.
4. **Section 5 & 6 (Documentation & Performance Deliverables)**:
   - Benchmarks in `docs/BENCHMARKS.md` lacked sync-committee period amortized cost tables, 1-yr and 5-yr LEZ state storage growth projections, end-to-end deposit-to-settlement latency breakdowns, and reconciliation of the 45s private path vs 54s log proof.
   - Test counts across `README.md`, `criteria-checklist.md`, and `security-review.md` required authoritative synchronization.

### Decision & Implementation
1. **Hardened Weak-Subjectivity Freshness Anchor Verification (Issue A)**:
   - In `handle_begin_update_authenticated` and `handle_attest_state_authenticated`, resolved `network_anchor = config.get_trusted_head(instance.chain_id)`. If missing, execution fails closed with `MosooError::InvalidBootstrap`.
   - Strictly enforced that if `network_anchor.saturating_sub(args.instance.current_slot) > CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS` (54,000 slots / ~7.5 days), execution fails closed immediately with `MosooError::WeakSubjectivityExpired { update_slot: network_anchor, current_slot: instance.current_slot }`.
   - Caller-supplied `trusted_head_slot` must satisfy `network_anchor <= s <= network_anchor + 54_000` and `s >= instance.current_slot`; invalid values fail closed with `MosooError::InvalidBootstrap`.
2. **Multi-Instance and Multi-Checkpoint Registries (Issue B)**:
   - Extended `TrustedBridgeConfig` with:
     ```rust
     #[serde(default)]
     pub trusted_instances_registry: HashMap<u64, HashSet<[u8; 32]>>,
     #[serde(default)]
     pub trusted_checkpoints_registry: HashMap<u64, HashSet<[u8; 32]>>,
     ```
   - Enhanced `is_trusted_or_unpinned` and `is_trusted_checkpoint` to support both multi-registries and legacy mappings.
   - Provided registration methods: `register_trusted_instance_in_registry`, `register_trusted_checkpoint_in_registry`, and authorized variants.
3. **Canonical Network Constants & On-Chain Administrative Instructions (Section 3)**:
   - Added canonical constants: `CANONICAL_MAINNET_CHECKPOINT_ROOT`, `CANONICAL_MAINNET_CHECKPOINT_SLOT` (`10_320_000`), `CANONICAL_MAINNET_CHECKPOINT_PERIOD` (`1259`), `CANONICAL_HOLESKY_CHECKPOINT_ROOT`, `CANONICAL_HOLESKY_CHECKPOINT_SLOT` (`3_250_000`), `CANONICAL_HOLESKY_CHECKPOINT_PERIOD` (`396`).
   - Added `GuestInstruction::RegisterNetworkCheckpoint` and `GuestInstruction::RegisterTrustedInstance`, dispatched via `dispatch_register_network_checkpoint` and `dispatch_register_trusted_instance` in `LezRuntimeAdapter<S>`.
   - Instructions require authorization by the configured `admin_authority`, failing unauthorized callers with `MosooError::DomainSeparationFailed`.
4. **Documentation & Performance Harmonization (Section 5 & 6)**:
   - Reconciled 45s typical proving latency vs 54s Tier C worst-case upper bound in `docs/BENCHMARKS.md`.
   - Added sync-committee period amortized cost table showing 93.2% gas reduction at scale.
   - Added 1-yr and 5-yr LEZ state storage growth projections (< 31 MB at 100k claims/yr).
   - Added end-to-end latency breakdown (~13.4 min total, with Casper FFG finality driving > 95% of duration).
   - Added in-program BLS vs native host precompile comparison matrix.
   - Harmonized test inventory: **317 Rust tests** + **16 Foundry EVM tests** = **333 total passing tests** with 0 warnings.

