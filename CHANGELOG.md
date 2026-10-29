# Changelog

All notable changes to the Mosoo project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-29

### Added
- **LEZ v0.4 Conformance & Acceptance Gate**: Hardened 18/18 deterministic acceptance tests validating isolated state transition boundaries and strict gas ceilings.
- **Admin Authority One-Time Bootstrap**: Added `handle_bootstrap_admin_authority` to `TrustedBridgeConfig` allowing initial governance bootstrapping while rejecting replay attempts with `AlreadyInitialized`.
- **Effective Instance Head Freshness**: Integrated `get_effective_instance_head` into authenticated update and state attestation handlers with fail-closed fallback to chain-wide anchor heads.
- **Adversarial Mutation Test Suite**: 50 test functions rejecting 42 distinct mutation attack vectors covering consensus forks (Altair through Gloas), replay, and immutability invariants.
- **Security Hardening Regression Suite**: 58 regression tests covering state transitions, boundaries, and overflow limits.
- **Two-Way Bridge Hardening**: 16 Foundry tests for `MosooLocker.sol` on Sepolia verifying rolling 24h withdrawal limits, timelock governance, and independent guardian veto.

### Changed
- Refactored consensus trust assumptions (`docs/TRUST_ASSUMPTIONS.md`), cleanly delineating 256-epoch sync committee rotation from dynamic PoS weak-subjectivity and Mosoo dual operational/safety windows.
- Synchronized authoritative test suite counts across documentation and execution traces: 334 total tests passing (318 Rust workspace tests + 16 Foundry EVM tests).
- Replaced absolute security terminology with rigorous cryptographic hardness and zkVM soundness statements.

## [0.2.0] - 2026-10-28

### Added
- **Two-Way Bridge Architecture (`MosooLocker.sol`)**: Deployed canonical Solidity vault on Ethereum Sepolia (`0x74625D146B8d9413F3c3976B323d94A739be7856`) with rolling 24-hour rate limiting, 2-day timelocked governance, Guardian veto, and replay-protected burn-to-unlock settlement.
- **Public LEZ v0.3.1 Testnet Verification**: Live consensus and gas verification against `https://testnet.lez.logos.co` (Block height > 68,400) and Sepolia bridge deposit tracing (`0x3ab00f...`).
- **Cryptographic Trust Assumptions & Threat Model (`docs/TRUST_ASSUMPTIONS.md`)**: Formalized checkpoint provenance, 2/3 honest sync committee quorum assumptions, off-chain daemon safety vs liveness roles, and reorganization failure conditions.
- **Audited Light-Client Prior Art Assessment**: Extended ADR-003 with technical evaluation of `r0vm-helios` (Boundless), delineating Altair math reuse from custom 3-Tx gas split and audit surface boundaries.
- **Recommended Consumer Pattern**: Documented atomic same-transaction claim pattern in `docs/CONSUMERS.md` and `README.md` with typed error handling and fail-closed guarantees.
- **Logos Module Release Action CI**: Added `.github/workflows/logos-modules-release.yml` automating packaging and validation for the Logos Core Module Catalog.
- **Test Suite Expansion**: Grew test suite to 333 total passing tests (317 Rust workspace tests + 16 Foundry Solidity tests) with zero compiler or Clippy warnings (`-D warnings`).

### Changed
- Reconciled benchmark cycle numbers in `docs/BENCHMARKS.md` (Table 4 updated to canonical 2,890,000 cycles for end-to-end receipt log attestation).
- Aligned statement ID canonical derivation formula across all architectural documentation (`derive_statement_id_v2`).
- Positioned Logos Ethereum Core verified proxy (`LOGOS_ETHEREUM_CORE_RPC`) as canonical primary architecture for daemon consensus routing.

## [0.1.2] - 2026-10-21

### Added
- **Ethereum Fork Schedule (Electra & Fulu)**: Implemented complete consensus fork version mapping for Ethereum Mainnet (Deneb, Electra `0x05000000`, Fulu `0x06000000`), Sepolia (Capella, Deneb, Electra `0x90000075`, Fulu `0x90000076`), and Holesky (`0x04017000`, `0x05017000`, `0x06017000`). Added regression boundary tests across all fork transitions (`slot - 1`, `slot`, `slot + 1`).
- **Cryptographic Bootstrap Validation**: Upgraded `InitializeArgs` and `handle_initialize` to cryptographically prove the 512-validator `current_sync_committee` against `bootstrap_header.state_root` at generalized index 54 (`CURRENT_SYNC_COMMITTEE_GINDEX`). Added negative tests rejecting forged committees, corrupted branches, and stale checkpoints.
- **Mandatory Execution Payload**: Made `execution_payload_header` and generalized index 25 branch verification strictly mandatory on post-Merge Ethereum. Removed zero-root fallback (`[0; 32]`) completely; missing or malformed payloads reject immediately without advancing the chain head.
- **Receipt-Log Inclusion Prover**: Implemented `ReceiptLogProof`, `VerifiedLog`, `verify_receipt_log_proof`, and `decode_and_validate_receipt` in `mosoo-core/src/inclusion.rs`. Supports both EIP-2718 typed transaction receipts (`0x01`, `0x02`, `0x03`) and legacy receipts, verifying event emitters and event signatures (`Transfer`) against `HeaderRecord.receipts_root`.
- **End-to-End Consumer Event Claims**: Demonstrated full receipt-log verification to ERC-20 token claim with deterministic nullifier replay rejection in `tests/light_client_tests.rs`.
- **Test Suite Expansion**: Expanded workspace test suite from 33 to 49 passing tests (46 unit/integration + 3 doc-tests) with zero warnings under `cargo clippy --workspace --all-targets -- -D warnings` and clean `cargo fmt`.

## [0.1.1] - 2026-10-21

### Added
- Cryptographic in-guest BLS pairing pipeline: implemented `blst_two_miller_loops` and `blst_final_exp_and_verify` in `mosoo-core::crypto` and integrated them into the zkVM guest program. Tampered signatures are deterministically rejected at the `FinishUpdate` transaction.
- Authentic execution state root extraction: added `ExecutionPayloadHeader` and SSZ generalized index 25 Merkle branch verification against `BeaconBlockHeader.body_root`. `HeaderRecord` accounts now contain verified `execution_state_root` and `execution_block_hash`.
- Spec-compliant SSZ Merkleization for `SyncCommittee` (`Vector[BLSPubkey, 512]` + `aggregate_pubkey`) adhering strictly to Ethereum consensus layer specifications.
- Expanded workspace test suite to 33 tests (30 unit/integration + 3 doc tests) with tests for corrupted execution payload branches and tampered BLS signatures in the split pipeline.

## [0.1.0] - 2026-10-20

### Added
- Core Ethereum Altair light client data models and SSZ tree hash computations (`BeaconBlockHeader`, `SyncCommittee`, `SyncAggregate`).
- BLS12-381 pairing verification using RISC0-accelerated `blst`.
- Merkle-Patricia Trie (MPT) inclusion prover for account balance and contract storage slot verification via `alloy-trie`.
- Predicate engine evaluating state conditions and generating collision-resistant nullifiers (`VerifiedStatement`).
- 3-transaction split pipeline (`begin_update`, `miller_update`, `finish_update`) complying with the LEZ ~10M gas cap.
- Dual reference consumers:
  - `erc20-receiver`: trustless ERC-20 equivalent token minting with duplicate claim rejection.
  - `ether-receiver`: trustless native ETH accounting with balance threshold checks.
- Permissionless consensus update daemon with randomized jitter against frontrunning and submission griefing.
- Interactive terminal developer CLI (`mosoo-cli`) with demo walkthrough, benchmark breakdown, and specification inspect commands.
- End-to-end integration test suite and CI workflows on GitHub Actions.
