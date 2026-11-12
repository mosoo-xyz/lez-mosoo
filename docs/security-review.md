# Mosoo Security Architecture & Threat Review

This document describes the core security invariants enforced by Mosoo (`mosoo-core`, consumer crates, `mosoo-daemon`, and `contracts/MosooLocker.sol`), their test coverage across the workspace, and current audit boundaries.

---

## Core Protocol Invariants

1. **Consensus Domain Separation & Fork Binding:** `compute_signing_root` binds `DOMAIN_SYNC_COMMITTEE` (`0x07000000`), chain-specific fork versions, and `genesis_validators_root`. Cross-chain or cross-fork signatures fail pairing checks.
2. **Fork-Aware Execution Payload Merkleization:** Pre-Deneb headers pad to 16 SSZ leaves (depth 4); Deneb, Electra, Fulu, and Gloas headers pad to 32 leaves (depth 5) with length-mixed `extra_data` hashing so `execution_state_root` and `receipts_root` match Ethereum consensus layouts without silent truncation.
3. **Bootstrap Committee Authentication:** `handle_initialize` verifies initial sync committees against `bootstrap_header.state_root` via generalized index `54` / `86` (`current`) and `55` / `87` (`next`), rejecting tampered committee roots before any state is written.
4. **Historical Block Accumulator Anchoring:** Proofs referencing historical slots use fork-aware generalized indices (`(37 << 13) | (slot % 8192)` for Altair–Deneb; `(69 << 13) | (slot % 8192)` for Electra–Fulu) anchored in the authenticated `BeaconState.block_roots` accumulator rather than unverified caller headers.
5. **Cross-Stage 3-Tx Pipeline Binding (`update_digest`):** `JobAccount` PDAs derive deterministically from `(instance_id, job_id)` and record `update_digest = sha256(slot || attested_root || finalized_root || bits || signature)`. Both `handle_miller_update` and `handle_finish_update` reject updates whose digest, chain, instance, or stage mismatches.
6. **Store-Backed Authenticity & Atomic Consumer Verification:** Consumers load `InstanceAccount` and `HeaderRecord` from program-owned storage (`store.get_account_owner == MOSOO_PROGRAM_ID`) rather than caller memory, pin trusted instances and lockers via `TrustedBridgeConfig`, and execute state/receipt verification atomically inside `claim_atomic` / `claim_ether_atomic`.
7. **Collision-Resistant Log Payloads & Nullifiers:** Log data above 32 bytes is domain-hashed (`keccak256("MOSOO_EVENT_PAYLOAD_HASH:" || data)`), while event subject keys bind `block_hash || slot || tx_index || log_index || emitter || topic0`.
8. **Strict Merkle Branch Depth Validation:** `compute_branch_root_checked` enforces exact SSZ branch depth `branch.len() == (63 - gindex.leading_zeros())`, preventing path-extension or truncation malleability.
9. **Instance Immutability & Weak-Subjectivity Caps:** Initialized light client instances cannot have genesis checkpoints rewritten in place. Freshness enforces an operational window (`CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS = 54,000` slots, ~7.5 days) and a hard dormancy ceiling (`MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS = 1,728,000` slots, ~240 days).
10. **Canonical V2 Statement IDs:** `derive_statement_id_v2` computes `sha256("mosoo_statement_v2" || chain_id || genesis_validators_root || subject_key || proof_type_tag || verified_value)` independently of predicate thresholds (`AtLeast`, `Equal`, etc.), blocking predicate-tweaked replay claims. Consumers reject mismatched caller-supplied IDs with `StatementIdMismatch`.
11. **Escrow-Backed Asset Minting Separation:** Minting wrapped assets (`MethLedger::mint_meth_atomic`, `Erc20Ledger` atomic deposits) requires `StatementBinding::NativeEthDeposit` or verified ERC-20 `MosooLocker` deposit receipts, rejecting unbacked account-balance proofs (`DepositBackingRequired`) and untrusted locker addresses.
12. **Persistent PDA Nullifiers:** Consumed claim IDs persist in deterministic PDA records (`["mosoo_nullifier", statement_id]`) with atomic state rollback if ledger updates fail.

---

## Off-Chain Daemon & Two-Way Bridge Guards

- **Local Transaction Signing (`mosoo-daemon` & `mosoo-cli`):** Private keys stay inside `alloy::signers::local::PrivateKeySigner`; only caller addresses and signatures cross RPC boundaries, never raw secrets.
- **Fail-Closed Period Transitions:** Syncing across 8,192-slot sync-committee periods requires `/light_client/updates` with `next_sync_committee` proof branches; the daemon refuses fallback to `/light_client/finality_update` without committee handoff data.
- **Escrow Vault Hardening (`contracts/MosooLocker.sol`):**
  - Contract-scoped EIP-712 `DOMAIN_SEPARATOR` (`chainId` + `verifyingContract`) and `M-of-N` quorum signatures (Sepolia v2 commissioned at `2-of-2`) with EIP-2 low-`s` enforcement and non-zero signer checks.
  - Default-enabled token allowlist (`tokenAllowlistEnabled = true`), fee-on-transfer balance-delta verification, and safe staticcall balance checks.
  - `executedBurns` and permanent `cancelledBurns` nullifier mappings.
  - Rolling 24-hour withdrawal caps with bounded cleanup (`MAX_CLEANUP_BATCH = 32`), 24-hour queue + Guardian veto (`>= 10 ETH`), 24-hour `attesterAuthority` delay, two-step ownership handover, and 48-hour multisig governance timelocks (`GOVERNANCE_TIMELOCK_DELAY = 2 days`).

---

## Automated Security Test Coverage

| Suite | Location | Scope |
| :--- | :--- | :--- |
| Security Hardening (`58`) | `mosoo-core/tests/security_hardening_tests/` | Account ownership checks, pinned instances/check-points, deposit separation, fork adapters, freshness bounds (`guest_and_store`, `privacy_and_instance`, `deposit_and_forks`, `freshness_and_adapter`) |
| Adversarial Mutation (`50`) | `mosoo-core/tests/adversarial_mutation_tests/` | Forged signatures, quorum deficits, period skips, Gloas RLP tampering, replay attacks, cross-stage job tampering, storage poisoning (`consensus_and_branches`, `state_and_replay`, `pipeline_and_storage`, `instance_and_config`) |
| Two-Way Bridge (`24`) | `mosoo-core/tests/two_way_bridge_tests.rs` | Burn ID integrity, EIP-712 cross-contract replay rejection, rate limits, guardian veto paths, and RISC Zero outbound burn journal encoding |
| Privacy & Correlation (`6`) | `mosoo-core/tests/privacy_and_correlation_tests.rs` | Confidential commitment blinding and `DepositCommitted` unlinkability guarantees |
| Solidity Escrow & ZK Verifier (`31`) | `contracts/test/` | Foundry unit & fuzz tests against live EVM semantics (`MosooLocker.t.sol` 27 + `MosooZkBurnVerifier.t.sol` 4) |
| Evidence Mutation (`7`) | `scripts/test-evidence-mutation.py` | Tampered hashes, cycle caps, and missing artifacts rejected by `verify-evidence.py` |

For exact suite counts and execution commands, see [`docs/TESTING.md`](TESTING.md).

---

## Privacy & Known Audit Boundaries

- **Shielded L1 Deposits vs. Public LEZ Execution:** `MosooLocker` v2 (`depositShieldedETH` / `DepositCommitted`) omits plaintext `lezRecipient` from Ethereum logs, and `PrivacyMode::Confidential` blinds `StatementAccount` data with explicit caller salt. However, LEZ consumers still verify transaction receipts and Merkle proofs directly in Rust rather than inside an anonymous Groth16 circuit; hiding `tx_index`/`log_index` on public LEZ belongs to future RFP-022 work.
- **Runtime Scopes & Hardening:** Live immutable LEZ v0.3.1 `mosoo_lc` (`Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg`) runs the archived `artifacts/programs/v0.3/mosoo_lc.bin` binary (rebuilt binary verified in `V03State` local simulation; live redeployment awaits depleted public testnet faucet replenishment), and hardened EIP-170 `MosooLocker` v4 (`0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd`, `productionCommissioned = true`, irreversible `shieldedDepositsOnly = true` & `strictFixedDenominationMode = true`, `legacyRoutesPermanentlyDisabled = true`, payload-bound large ETH/ERC-20 withdrawal queue, `owner != guardian`, non-zero daily limits) is live on Sepolia. In `mosoo-core` (`v0.4` target), `GuestInstruction::StoreBacked` is gated out of production `methods/guest` builds (`#[cfg(any(test, feature = "test-harness"))]`), `LezRuntimeAdapter` / `dispatch_store_instruction_with_signer` binds admin/bootstrap actions to verified runtime signers, and `mosoo-core/src/inclusion.rs` enforces strict EIP-658 `status == [1u8]`, exact receipt/log RLP field counts, and proof byte/node caps while public LEZ `v0.4` remains unreleased.
- **Deprecated Legacy Entrypoints:** Historical unauthenticated helpers in `mosoo-core` and consumer crates carry `#[deprecated]` annotations to guard against accidental misuse; production callers must use `claim_atomic`, `claim_ether_atomic`, and strict `TrustedBridgeConfig` paths.
- **External Security Audit:** Internal security hardening and mutation tests cover protocol boundaries documented here; an independent third-party audit has not yet been completed and is planned before mainnet deployment.
