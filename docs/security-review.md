# Mosoo Security Architecture, Invariant Testing & Threat Model

This document specifies the cryptographic threat model, core protocol invariants, adversarial test suite, and independent audit plan for the **Mosoo Ethereum Consensus & State Attestation Module** on the Logos Execution Zone (LEZ).

> [!NOTE]
> **Security & Verification Status:**
> - **Internal Hardening & Test Suite:** Internal adversarial invariant hardening, protocol boundary enforcement, 42 mutation attack tests (`tests/adversarial_mutation_tests.rs`), 58 security hardening regression tests (`tests/audit_oct26_hardening_tests.rs`), 22 two-way cross-chain bridge security tests (`tests/two_way_bridge_tests.rs`), 16 Foundry EVM tests, and a total of 334 tests (318 Rust + 16 Foundry) passing in CI with 0 compiler or Clippy warnings (`-D warnings`).
> - **Independent External Audit:** Planned formal third-party security audit engagement prior to mainnet release.

---

## 1. Threat Model & Trust Assumptions

Mosoo operates as an on-chain Ethereum consensus verification engine and state prover inside the RISC Zero zkVM on LEZ. The security architecture addresses the following threat vectors:

### Consensus Layer Assumptions & Cryptographic Thresholds
- **Safety Threshold (>= 342 / 512 Signers):** The light client enforces Ethereum's 2/3 aggregate participation threshold (>= 342 of 512 sync committee validators). Under the standard Ethereum consensus security model, an adversary cannot forge a valid BLS aggregate signature over an invalid or fabricated block header unless Byzantine actors control at least 342 validators (a >= 2/3 Byzantine supermajority).
- **Liveness Threshold (<= 170 / 512 Byzantine / Offline Validators):** If more than 170 validators (> 1/3 of the 512 sync committee) fail to participate or are Byzantine, the remaining honest validators (< 342) cannot reach the 2/3 quorum. In this scenario, header updates temporarily stall until validator participation recovers or the committee rotates at the next period boundary (~8,192 slots / ~27.3 hours). This is a liveness halt, not a safety violation (no invalid headers can be accepted).
- **Sync Committee Rotation Period (8,192 Slots / 256 Epochs):** The 512-validator sync committee rotates every 256 epochs (8,192 slots, ~27.3 hours). The next sync committee is authenticated via Merkle branch against the attested state root at fork-aware generalized indices (55 for Altair/Deneb, 87 for Electra/Fulu, 2946 for Gloas).
- **Weak-Subjectivity Freshness Window (54,000 Canonical Slots / 1,728,000 Slots Ceiling):** In Ethereum PoS, weak subjectivity defines the period within which an offline light client must sync or obtain a trusted checkpoint to remain safe against long-range consensus forks. Mosoo implements a two-tier defense: a canonical operational window of 54,000 slots (`CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS`, ~7.5 days at 12s/slot) for routine sync updates, and a hard consensus ceiling of 1,728,000 slots (`MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS`, 54,000 epochs / ~240 days) on bootstrap checkpoints and historical leaps (`WeakSubjectivityExpired`). Per RFP-021 Functionality #13, verified instances are strictly immutable and cannot be rewritten in-place. Stale instances stalled past this window are retired and replaced by initializing a fresh instance with a current trusted checkpoint per Functionality #10. Updates asserting slot numbers retrogressive to the tracked checkpoint are rejected by monotonicity checks (`StaleUpdate`).

### Untrusted Prover & Environment Assumptions
- **Byzantine Operator / Host VM:** The zkVM guest code makes zero assumptions about the honesty of the transaction submitter or the LEZ host VM. All Merkle branches, signatures, and RLP encodings are validated in-guest.
- **Untrusted Consumer Caller:** Consumer smart contracts cannot trust caller-supplied claims. State inclusion proofs and predicate evaluations execute directly against an authenticated `HeaderRecord` committed by Mosoo.
- **Replay & Double-Spend Attacks:** Any state claim (e.g. token deposit, event log emission) must be claimable exactly once across all transactions, slots, and fork boundaries.

---

## 2. Core Protocol Invariants & Boundary Hardening

During protocol design and engineering, we identified and hardened eight critical boundary conditions:

### Invariant 1: Quorum & Sync Aggregate Strictness
**Vulnerability:** Altair sync committees consist of 512 validators represented as a 64-byte bitfield and a 96-byte aggregate BLS signature. If bitfield length is not strictly enforced, an attacker could supply trailing bytes with set bits. With 341 valid signers, adding an extraneous bit would bypass the 342/512 threshold without corresponding to any validator in the committee.  
**Enforcement:** `verify_sync_aggregate_lengths()` strictly asserts `bits.len() == 64` and `signature.len() == 96`:
```rust
pub const SYNC_COMMITTEE_BITS_BYTES: usize = 64;
pub const BLS_SIGNATURE_BYTES: usize = 96;

pub fn verify_sync_aggregate_lengths(bits: &[u8], signature: &[u8]) -> Result<(), MosooError> {
    if bits.len() != SYNC_COMMITTEE_BITS_BYTES {
        return Err(MosooError::InvalidSyncCommitteeBitsLength {
            actual: bits.len(),
            expected: SYNC_COMMITTEE_BITS_BYTES,
        });
    }
    if signature.len() != BLS_SIGNATURE_BYTES {
        return Err(MosooError::InvalidSyncCommitteeSignatureLength {
            actual: signature.len(),
            expected: BLS_SIGNATURE_BYTES,
        });
    }
    Ok(())
}
```
*Validated in:* `test_sync_committee_bits_strict_64_bytes_enforcement` and `test_mutation_attack_2_sub_threshold_quorum_rejected`.

---

### Invariant 2: Multi-Fork SSZ Compatibility (Deneb 32 Leaves)
**Vulnerability:** Pre-Deneb execution payload headers contain 14 or 15 fields, padding to 16 leaves (depth 4). Deneb introduced `blob_gas_used` and `excess_blob_gas`, bringing the field count to 17. Merkleizing 17 fields into a 16-leaf tree silently corrupts the computed root. Additionally, SSZ `ByteList[32]` for `extra_data` requires hashing the 32-byte chunk mixed with length bytes.  
**Enforcement:** Dynamic Merkleization pads to 16 leaves for Bellatrix/Capella and 32 leaves (depth 5) for Deneb/Electra/Gloas, with length-mixed `extra_data` hashing:
```rust
let mut chunk = [0u8; 32];
chunk[..header.extra_data.len()].copy_from_slice(&header.extra_data);
let mut len_bytes = [0u8; 32];
len_bytes[..8].copy_from_slice(&(header.extra_data.len() as u64).to_le_bytes());
let mut h = Sha256::new();
h.update(chunk);
h.update(len_bytes);
let extra_data_root: [u8; 32] = h.finalize().into();
```
*Validated in:* `test_deneb_execution_payload_header_32_leaves` and `test_sepolia_gloas_and_hoodi_fork_boundary_and_domain_separation`.

---

### Invariant 3: Bootstrap Checkpoint Committee Authentication
**Vulnerability:** If `initial_next_committee` is supplied during bootstrap initialization (`handle_initialize`), storing it without verifying its Merkle proof allows an attacker to plant a malicious sync committee that activates upon the next period boundary.  
**Enforcement:** `InitializeArgs` requires `initial_next_committee_branch`. When provided, it is cryptographically verified at generalized index 55 against `bootstrap_header.state_root`.  
*Validated in:* `test_mutation_attack_11_bootstrap_next_committee_branch_verification_and_forgery_rejection`.

---

### Invariant 4: Historical Block Root Accumulator Anchoring
**Vulnerability:** Proving past Ethereum blocks against `instance.current_header_hash` fails because the beacon block header hash is not the beacon state root.  
**Enforcement:** Historical block proofs compute fork-aware generalized indices: `(37 << 13) | (slot % 8192)` (depth 18) for Altair..Deneb, or `(69 << 13) | (slot % 8192)` (depth 19) for Electra..Fulu, and verify the branch directly against the `BeaconState.block_roots` accumulator anchored in `instance.current_state_root`.  
*Validated in:* `test_mutation_attack_12_historical_block_roots_accumulator_proof_anchor_and_rejection`.

---

### Invariant 5: Cross-Stage Pipeline Binding (`update_digest`)
**Vulnerability:** Splitting BLS pairing verification into 3 transactions (`begin_update` -> `miller_update` -> `finish_update`) coordinates through an on-chain `JobAccount` PDA. Without cryptographic binding between stages, an attacker could tamper with `job.update` between stages 2 and 3.  
**Enforcement:** `JobAccount` records `update_digest`:
```text
update_digest = sha256(slot || attested_root || finalized_root || bits || signature)
```
Both `handle_miller_update` and `handle_finish_update` recompute and verify this digest.  
*Validated in:* `test_mutation_attack_10_cross_stage_job_tampering_and_digest_mismatch_rejected`.

---

### Invariant 6: Atomic Same-Transaction Consumer Settlement
**Vulnerability:** If reference consumers accept caller-supplied statements out-of-band, an attacker could fabricate a statement struct without valid consensus backing.  
**Enforcement:** `claim_atomic` in `erc20-receiver` and `claim_ether_atomic` in `ether-receiver` execute state proof verification directly against the light client's authenticated `HeaderRecord` within the consuming transaction. Any forged proof or invalid header causes the entire transaction to revert atomically.  
*Validated in:* `test_claim_atomic_receipt_log_succeeds`, `test_claim_ether_atomic_account_balance_succeeds`, and negative rejection tests in both consumer crates.

---

### Invariant 7: Collision-Resistant Event & Statement Nullifiers
**Vulnerability:** Variable-length event logs with identical trailing bytes could collide if naively truncated to 32 bytes. Identical transfers in different blocks could also produce colliding nullifiers.  
**Enforcement:** Event payloads > 32 bytes use domain-separated Keccak-256 hashing: `keccak256("MOSOO_EVENT_PAYLOAD_HASH:" || data)`. Event subject keys explicitly bind `block_hash || slot || tx_index || log_index || emitter || topic0`.  
*Validated in:* `test_variable_length_log_data_prevents_silent_truncation_collision` and `test_mutation_attack_9_cross_block_event_nullifier_uniqueness`.

---

### Invariant 8: Strict Merkle Proof Depth Validation
**Vulnerability:** Accepting variable-length Merkle branches without enforcing depth permits path malleability attacks.  
**Enforcement:** `compute_branch_root_checked()` verifies that branch length exactly matches tree depth: `branch.len() == (63 - gindex.leading_zeros())`.  
*Validated in:* `test_branch_depth_strict_validation` and `test_mutation_attack_4_forged_committee_branch_rejected`.

---

### Invariant 9: Genesis Bootstrap Weak-Subjectivity Boundary & Authority Provenance
**Vulnerability:** Bootstrapping a light client from a stale or attacker-controlled initial state allows long-range fork attacks.
**Enforcement:** In alignment with Ethereum PoS specification (`sync-protocol.md`), initial sync committees are verified at generalized index 54/86 against `bootstrap_header.state_root`. A mandatory `trusted_head_slot` ensures weak-subjectivity freshness ($\le 1,728,000$ slots / ~240 days). Once initialized, the instance is permanently immutable, and all future updates require BLS quorum ($\ge 342/512$) with zero operator trust.  
*Validated in:* `test_security_audit_attack_23_mandatory_weak_subjectivity_freshness_rejected` and `test_weak_subjectivity_and_stale_instance_recovery`.

---

### Invariant 10: Canonical Statement ID Integrity & Decoupled State Derivation
**Vulnerability:** If consuming contracts simply trust a caller-supplied `statement_id`, an attacker can modify the identifier to bypass nullifiers while pointing to the same underlying state.  
**Enforcement:** Consumers strictly recompute `statement.derive_canonical_id()` from the canonical state tuple:
$$\text{statement\_id} = \text{sha256}(\text{"mosoo\_statement\_v1"} \parallel \text{chain\_id} \parallel \text{subject\_key} \parallel \text{proof\_type} \parallel \text{value})$$
Any mismatch triggers an immediate fail-closed `StatementIdMismatch` error.  
*Validated in:* `test_security_audit_attack_37_tampered_statement_id_nullifier_bypass_rejected` and `test_erc20_claim_rejects_statement_id_tampering`.

---

### Invariant 11: Economic Separation of Read-Only Attestation vs Escrow-Backed Asset Minting
**Vulnerability:** Allowing ordinary Ethereum account balance proofs (`StatementBinding::Account`) to mint synthetic `mETH` on LEZ enables infinite unbacked minting without real collateral.  
**Enforcement:** Dual-interface separation: read-only access gating (`claim_ether`) allows balance proofs, while bridge minting (`MethLedger::mint_meth_atomic`) strictly enforces `StatementBinding::NativeEthDeposit` from verified `MosooLocker.sol` escrow receipts, rejecting unbacked balance claims with `DepositBackingRequired`.  
*Validated in:* `test_security_audit_attack_36_unbacked_ethereum_balance_bridge_minting_rejected` and `test_meth_ledger_mint_atomic_rejects_unbacked_account_balance`.

---

### Invariant 12: LEZ PDA-Backed Nullifier Persistence & Recovery
**Vulnerability:** In-memory nullifier sets lose state upon contract upgrades or node restarts, allowing replay of historic claims.  
**Enforcement:** Nullifiers are modeled as deterministic LEZ runtime PDA accounts (`["mosoo_nullifier", canonical_statement_id]`) with exportable/restorable state structures (`export_pda_records` / `restore_pda_records`), guaranteeing crash persistence across LEZ block boundaries.  
*Validated in:* `test_erc20_nullifier_pda_derivation_and_restart_persistence` and `test_ether_nullifier_pda_derivation_and_restart_persistence`.

---

## 3. Automated Adversarial Test Harness

The adversarial test harness implements 50 automated test functions covering 42 distinct mutation attack scenarios in `mosoo-core/tests/adversarial_mutation_tests.rs`:

| Test Name | Attack Scenario Tested | Expected Rejection |
| :--- | :--- | :--- |
| `test_mutation_attack_1` | Fabricated beacon header with forged signing root | `MosooError::InvalidSignature` |
| `test_mutation_attack_2` | Sub-threshold quorum (< 342/512 validators) | `MosooError::InsufficientParticipation` |
| `test_mutation_attack_3` | Non-64-byte sync committee bitfield | `MosooError::InvalidSyncCommitteeBitsLength` |
| `test_mutation_attack_4` | Forged next sync committee branch at gindex 55 | `MosooError::SyncCommitteeBranchInvalid` |
| `test_mutation_attack_5` | Non-monotonic slot updates (stale / retrogressive) | `MosooError::StaleUpdate` |
| `test_mutation_attack_6` | Cross-chain replay across Mainnet and Sepolia | `MosooError::DomainSeparationFailed` |
| `test_mutation_attack_7` | Corrupted MPT receipts & double-claim replay | `MosooError::InvalidTrieProof` / `AlreadyClaimed` |
| `test_mutation_attack_8` | State proof against unauthenticated header record | `MosooError::UnauthenticatedHeaderRecord` |
| `test_mutation_attack_9` | Cross-block event nullifier collision attempt | Unique statement IDs asserted |
| `test_mutation_attack_10`| Cross-stage job parameter tampering | `MosooError::JobDigestMismatch` |
| `test_mutation_attack_11`| Bootstrap unauthenticated next sync committee | `MosooError::BootstrapNextCommitteeBranchInvalid` |
| `test_mutation_attack_12`| Forged historical block accumulator root | `MosooError::UnauthenticatedHeaderRecord` |
| `test_security_audit_attack_13` | Repeat transfers between identical parties | Distinct nullifiers asserted & replay rejected |
| `test_security_audit_attack_14` | Silent arithmetic overflow / high-bit u64 truncation | Checked conversion error on values > u64::MAX |
| `test_security_audit_attack_15` | Malformed / truncated RLP length bounds | Fail-closed RLP decode error (zero panics) |
| `test_security_audit_attack_16` | Circular ring buffer slot aliasing beyond 8,192 slots | `MosooError::Internal` guard rejection |
| `test_security_audit_attack_17` | Replay invocation on terminated `Done` job stage | `MosooError::WrongJobStage` rejection |
| `test_security_audit_attack_18` | Statement ID tampering to bypass nullifier tracking | Catch by expected subject key validation |
| `test_security_audit_attack_19` | Backward slot rollback or expired checkpoint rewrite | Checkpoint immutability / `WeakSubjectivityExpired` |
| `test_security_audit_attack_20` | Reverted / failed transaction receipt (status = 0) | Reverted status check rejection |
| `test_security_audit_attack_21` | Out-of-order header slots (attested < finalized) | Temporal consistency rejection |
| `test_security_audit_attack_22` | Deeply nested predicate tree stack overflow DOS | Recursion depth limit (16 max) rejection |
| `test_security_audit_attack_23` | Mandatory weak-subjectivity freshness bounds | Fail-closed rejection on zero or expired slot |
| `test_security_audit_attack_24` | Unsatisfied condition predicate fail-closed behavior | `MosooError::PredicateFailed` (no statement) |
| `test_security_audit_attack_25` | Sync committee period jump > 1 period ($P_{sig} > P_{store} + 1$) | `MosooError::SyncCommitteePeriodSkip` |
| `test_security_audit_attack_26` | Period $P+1$ signature with missing next committee | `MosooError::MissingCommitteeBranch` |
| `test_security_audit_attack_27` | Previous-committee (period $P$) key used for period $P+1$ | `MosooError::InvalidSignature` |
| `test_security_audit_attack_28` | Committee rotation across period boundary | Verified rotation to `next_sync_committee` |
| `test_security_audit_attack_29` | Gloas ePBS tampered state/receipts roots | `MosooError::ExecutionPayloadBranchInvalid` |
| `test_security_audit_attack_30` | Gloas RLP execution header hash mismatch | `MosooError::GloasExecutionRlpMismatch` |
| `test_security_audit_attack_31` | Authentic beacon root with tampered execution roots | `MosooError::UnauthenticatedHeaderRecord` |
| `test_security_audit_attack_32` | Sequential multi-update boundary rotation invariant | Verified multi-update boundary progression |
| `test_security_audit_attack_33` | Predicate variation replay on identical Ethereum state | Enforce canonical state fact binding; invariant statement ID rejects altered predicate replay |
| `test_security_audit_attack_34` | Cross-instance job injection on same chain (RFP-021 #15) | Job PDA keying binds `instance_id` & `chain_id`; rejected with `JobInstanceMismatch` |
| `test_security_audit_attack_35` | Historical header proof closure & branch tampering (RFP-021 #6) | Fail-closed rejection across slot mismatches, window expiration, domain mismatch, and corrupted branches |
| `test_security_audit_attack_36` | Unbacked Ethereum account balance bridge minting attempt | Rejected with `EtherReceiverError::DepositBackingRequired`; zero unbacked synthetic mETH minted |
| `test_security_audit_attack_37` | Tampered statement ID nullifier bypass attempt | Consumers recalculate canonical statement ID; strictly rejected with `StatementIdMismatch` |
| `test_security_audit_attack_38` | Fabricated / uninitialized InstanceAccount attestation attempt | Rejected with `MosooError::NotInitialized` or `MosooError::InvalidBootstrap` |
| `test_mutation_attack_40` | Consumer claims referencing unpinned or unvetted instance account | Rejected with `MosooError::UnpinnedInstanceAccount` |
| `test_mutation_attack_41` | AccountStore state load from untrusted/unowned account | Rejected with `MosooError::InvalidAccountOwner` |
| `test_mutation_attack_42` | Checkpoint verification on caller-supplied memory struct rather than store | Checked on canonical store-loaded instance; caller spoofing rejected |
| `test_mutation_attack_46` | Dual nullifier atomic rollback on partial store failure | Atomic state rollback verified; zero orphaned nullifiers |

### 3.1 Two-Way Bridge Security & Escrow Defense Harness

Tested in `tests/two_way_bridge_tests.rs`:
- **Tampered Burn Receipt Defense (`test_two_way_bridge_adversarial_tampered_burn_id_rejected`):** Rejects forged burn identifiers or tampered recipients.
- **Strict EIP-712 Cross-Contract Replay Protection (Invariant 13) (`test_eip712_cross_contract_replay_protection`):**
  Binds `verifyingContract: address(this)` and `chainId: block.chainid` into EIP-712 structured data hashes (`BurnETH` / `BurnERC20`). An attester authority signature crafted for Locker contract A is cryptographically rejected if submitted to Locker contract B, preventing cross-deployment signature replay. Legacy un-namespaced `eth_sign` fallback has been completely removed.
- **Fail-Closed Token Allowlist (Invariant 14) (`test_token_allowlist_enforcement`):**
  The token allowlist is enabled by default (`tokenAllowlistEnabled = true`), preventing unvetted rebasing, fee-on-transfer, or adversarial ERC-20 tokens from being escrowed into the vault on initial deployment.
- **Inviolable Timelocked Authority Upgrades (Invariant 15) (`test_attester_authority_timelock_pipeline`):**
  Direct setters have been eliminated; all attester authority updates must pass through `proposeAttesterAuthority` with a mandatory 24-hour timelock delay before execution via `executeAttesterAuthority`.
  Enforces a mandatory 24-hour delay (`AUTHORITY_CHANGE_DELAY = 1 days`) between proposing a new `attesterAuthority` and executing the upgrade (`proposeAttesterAuthority` / `executeAttesterAuthority`), preventing instant unilateral authority key takeovers.
- **Rolling Daily Withdrawal Limits (Invariant 20) (`test_mosoo_locker_daily_withdrawal_limit_enforced`):**
  Enforces rolling 24-hour aggregate withdrawal volume limits for both ETH (`dailyWithdrawalLimitETH`) and ERC-20 tokens (`dailyWithdrawalLimitERC20`). Any withdrawal attempting to breach the 24-hour volume cap reverts with `DailyWithdrawalLimitExceeded()`, bounding maximum capital outflow velocity.
- **Large Withdrawal Timelock Queue & Permanent Guardian Veto (Invariant 21) (`test_mosoo_locker_large_withdrawal_queue_and_guardian_veto`, `test_mosoo_locker_proactive_guardian_veto_rejects_withdrawal`):**
  Withdrawals equal to or exceeding `LARGE_WITHDRAWAL_THRESHOLD_ETH` (default 10 ETH) or equivalent ERC-20 thresholds cannot be settled immediately. They are placed into an on-chain queue with a mandatory 24-hour challenge delay (`LARGE_WITHDRAWAL_DELAY = 1 days`). During this window, contract guardians or owners can execute `cancelQueuedWithdrawal(burnId)` or `cancelBurn(burnId)`. This permanently marks `cancelledBurns[burnId] = true`. Any subsequent attempt by a relayer or attacker to re-queue or unlock reverts immediately with `BurnCancelled()`, preventing bypass.
- **Ethereum Escrow Contract Security (`contracts/MosooLocker.sol`):**
  - Strict EIP-2 upper-bound on $s$-values ($s \le \text{0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0}$).
  - Non-zero signer check (`recovered != address(0)`).
  - Nullifier tracking (`executedBurns[burnId]`).
  - Permanent cancellation tracking (`cancelledBurns[burnId]`).
  - Fee-on-transfer balance differential verification on token deposits.
  - Safe token balance query (`_getTokenBalance` reverts with `BalanceQueryFailed()` on staticcall failure or short returns).
  - Two-step ownership handover (`transferOwnership` + `acceptOwnership`).
  - Foundry test harness (`contracts/test/MosooLocker.t.sol`, `foundry.toml`) for direct EVM execution and fuzzing.

- **Local Transaction Signing & Secret Isolation (Invariant 16):**
  The daemon and CLI parse operator private keys locally inside `alloy::signers::local::PrivateKeySigner`. The JSON-RPC envelope transmits only `from` and `signature` over RPC. Raw private key material is strictly prohibited from JSON parameters, HTTP payloads, error logs, and format strings (verified in `test_daemon_raw_private_key_never_sent_in_rpc_payload`).

- **Fail-Closed Period-Crossing Beacon Synchronization (Invariant 17):**
  Light client transitions crossing 8,192-slot period boundaries require `next_sync_committee` and its Merkle authentication branch. If `/light_client/updates` fails, the daemon fails closed immediately with an explicit error, refusing fallback to `/light_client/finality_update` which lacks committee handoff material.

- **Persistent AccountStore Nullifier Replay Defense (Invariant 18):**
  Consumer nullifiers are stored atomically in persistent `AccountStore` PDA records (`[b"nullifier", statement_id]` and `[b"ether_nullifier", statement_id]`). In-guest and host runtime execution verifies persistent account state, guaranteeing that replays are strictly rejected across full node restarts (verified in `test_sequencer_persistent_nullifier_atomic_claim_across_restart`).

- **InstanceAccount Provenance & PDA Authentication (Invariant 19):**
  Attestation verification verifies that instance accounts are loaded from authentic persistent PDA addresses (`["mosoo_instance", chain_id, instance_id]`) with verified non-zero instance IDs and valid bootstrap anchors, preventing fabricated instance injection (verified in `test_sequencer_fabricated_instance_account_rejected`).

---

## 4. Privacy & Zero-Correlation Guarantees

Mosoo shields claimant identity on LEZ via deterministic nullifiers:
- **Zero Address Leakage:** Claimant Ethereum addresses and signature bytes are not written to consumer contract state diffs.
- **Unlinkability:** Statement IDs act as one-way cryptographic nullifiers derived strictly from verified Ethereum state facts (ADR-006, RFP-021 Functionality #6):
  ```text
  statement_id = sha256("mosoo_statement_v2" || chain_id || genesis_validators_root || subject_key || proof_type_tag || verified_value)
  ```
- **Caveat:** Network-level traffic analysis (transaction timing, deposit amounts) remains observable on public chains.

Automated in [`mosoo-core/tests/privacy_and_correlation_tests.rs`](../mosoo-core/tests/privacy_and_correlation_tests.rs) (5 tests verifying zero address leakage and memory state diff shielding).

---

## 5. Independent Security Audit Plan

A formal third-party audit is planned prior to mainnet deployment:
- **Target Timeline:** Following public devnet deployment
- **Candidate Audit Firms:** Veridise, Trail of Bits, or Least Authority
- **Audit Scope:** In-guest `blst` pairing split, MPT trie verification logic, SPEL IDL deserialization safety, and consumer nullifier persistence.
