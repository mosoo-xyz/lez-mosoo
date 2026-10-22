# Changelog

All notable changes to the Mosoo project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
