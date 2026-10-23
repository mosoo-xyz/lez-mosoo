# Logos RFP-021 Technical Specification & Architecture Mapping

This document provides a technical mapping between the requirements in the [Logos RFP-021](https://github.com/logos-co/rfp) specification (*Trustless Ethereum State Attestation for LEZ*) and the architecture, crate implementations, and verification evidence in the Mosoo repository.

---

## 1. Core Protocol Requirements

| Specification Requirement | Architectural Component | Implementation & Test Reference |
| :--- | :--- | :--- |
| **Sync Committee Tracking** | Ethereum Altair 512-validator sync committee consensus tracker running inside RISC Zero zkVM guest | `mosoo-core/src/types.rs`, `mosoo-core/src/verifier.rs`, verified against canonical Period 1884 Ethereum vectors in `tests/light_client_tests.rs` |
| **BLS12-381 Aggregate Verification** | Pairing verification of aggregate BLS signatures over signing root using optimized `blst` | `mosoo-core/src/crypto.rs` (`blst_two_miller_loops`, `blst_final_exp_and_verify`), 3-Tx split pipeline tested in `crypto::tests::test_pairing_split_begin_miller_finish` |
| **Execution State Root Authentication** | Execution payload header / block hash Merkle branch verification against beacon body root (gindex 25 for Altair..Fulu, gindex 2856 for Gloas ePBS) | Handled in `mosoo-core/src/verifier.rs:verify_execution_payload_branch` with dynamic depth handling for Capella (16 leaves), Deneb/Electra (32 leaves), and Gloas (gindex 2856); tested in `light_client_tests::test_sepolia_gloas_execution_block_hash_branch_verification` |
| **Committee Handoff** | Period boundary transition (8,192 slots, ~27.3 hours) with next sync committee Merkle branch at fork-aware gindex (55 for Altair/Deneb, 87 for Electra/Fulu, 2946 for Gloas) | `mosoo-core/src/verifier.rs:verify_sync_committee_branch`, tested in `tests/light_client_tests.rs:test_electra_and_fulu_authentic_branch_verification_and_altair_rejection` |
| **Weak-Subjectivity Anchor** | Bootstrap from trusted checkpoint slot and committee (gindex 54 for Altair/Deneb, 86 for Electra/Fulu, 2945 for Gloas) | Cryptographic validation against beacon state root with weak subjectivity bounds (`tests/light_client_tests::test_weak_subjectivity_and_stale_instance_recovery`) |
| **Multi-Network Support** | Isolated instances per Ethereum chain ID | Domain separation and complete fork schedule (Bellatrix through Gloas) in `mosoo-core/src/crypto.rs`; tested across Mainnet (1), Sepolia (11155111), Holesky (17000), and Hoodi (560048) |
| **State Inclusion Prover** | Merkle-Patricia Trie (MPT) proofs for account balances and contract storage slots | `mosoo-core/src/inclusion.rs` using `alloy-trie`; state binding verified in `verifier.rs:handle_attest_state` |
| **Receipt Log Prover** | MPT receipt inclusion and event log extraction (legacy and EIP-2718 typed receipts) | `mosoo-core/src/inclusion.rs:verify_receipt_log_proof`, tested against simulated EIP-1559 transfer receipts in `inclusion::tests` |
| **Predicate Evaluation Engine** | Logical evaluation over verified state facts (`Equal`, `AtLeast`, `LessThan`, `All`, `Any`) | `mosoo-core/src/predicate.rs` with compound condition support |
| **Deterministic Statement IDs** | Unique nullifiers derived from verified consensus and state data for replay resistance | `mosoo-core/src/predicate.rs:derive_statement_id` bound to chain ID, subject key, proof type, value, and predicate; prevents cross-block and cross-chain replay |
| **Consensus Update Daemon** | Permissionless headless service monitoring beacon RPCs and submitting updates to LEZ | `daemon/src/main.rs`: REST Beacon API poller, JSON-RPC submitter, randomized jitter backoff, and competing-update recovery; tested in daemon unit tests |
| **Reference Consumers** | Working consumer dApps demonstrating on-chain state consumption | `consumers/erc20-receiver` (token minting) and `consumers/ether-receiver` (native ETH accounting) supporting both atomic same-transaction and decoupled relayer flows |

---

## 2. Execution Zone Constraints & Architecture

| Architectural Area | Design Implementation | Engineering Evidence |
| :--- | :--- | :--- |
| **10M Gas Cap Compliance** | 3-transaction split pipeline via `JobAccount` PDA: `begin_update` (~5.38M gas), `miller_update` (~4.18M gas), `finish_update` (~3.74M gas) | Every transaction operates with 46% to 62% safety margin below the ~10M LEZ gas limit; benchmarked in [`docs/BENCHMARKS.md`](BENCHMARKS.md) |
| **Atomic Same-Tx Consumption** | Direct in-guest execution of state proof verification and predicate evaluation inside the consuming transaction (`claim_atomic`, `claim_ether_atomic`) | Tested in `consumers/erc20-receiver` and `consumers/ether-receiver` unit tests; verified against forged headers and replay |
| **On-Chain Nullifier Enforcement** | Deterministic PDA derivation (`[b"nullifier", statement_id]`) preventing double-spending at consensus layer | Tested in `tests/e2e_consumer_tests.rs` and standalone sequencer harness |
| **Zero Precompile Dependency** | Full in-guest pairing execution inside RISC Zero zkVM; zero modifications required on LEZ host VM | Clean guest binary (103,424 bytes); documented in [`docs/REPRODUCE.md`](REPRODUCE.md) |
| **Logos SPEL IDL Definition** | Canonical SPEL schema, instruction interfaces, and error codes for Logos Core catalog | `mosoo-core/src/spel.rs` and [`docs/SPEL_IDL.md`](SPEL_IDL.md) |
| **Logos Core Verified Proxy** | RPC proxy endpoint routing for Ethereum beacon and execution endpoints | `daemon/src/main.rs` (`test_logos_ethereum_core_proxy_url_derivation`) and [`docs/DAEMON.md`](DAEMON.md) |

---

## 3. Adversarial Security & Edge Cases Remediated

All 12 adversarial attack classes are covered by automated integration tests (`tests/adversarial_mutation_tests.rs`):

1. **Fabricated Beacon Header**: Rejection of unsigned or forged beacon headers (`MosooError::InvalidSignature`).
2. **Sub-Threshold Participation**: Rejection of updates with < 342/512 validator quorum (`MosooError::InsufficientParticipation`).
3. **Invalid Bitfield Length**: Rejection of sync committee bitfields not strictly 64 bytes (`MosooError::InvalidSyncCommitteeBitsLength`).
4. **Non-Monotonic Slot Updates**: Rejection of stale or retrogressive slots (`MosooError::StaleUpdate`).
5. **Forged Committee Branch**: Rejection of forged next sync committee branches at gindex 55 (`MosooError::SyncCommitteeBranchInvalid`).
6. **Corrupted Execution Payload Branch**: Rejection of altered execution roots in Deneb/Electra 32-leaf branches (`MosooError::ExecutionPayloadBranchInvalid`).
7. **Cross-Chain Replay**: Domain separation enforcement across Mainnet, Sepolia, Holesky, and Hoodi (`MosooError::DomainSeparationFailed`).
8. **Corrupted MPT Receipt**: Rejection of tampered Merkle-Patricia Trie nodes (`MosooError::InvalidTrieProof`).
9. **Unauthenticated Header Record**: Rejection of state proofs against uncommitted or unfinalized headers (`MosooError::UnauthenticatedHeaderRecord`).
10. **Cross-Block Nullifier Collisions**: Derivation of unique receipt log subject keys incorporating block hash, slot, tx index, and log index.
11. **Cross-Stage Job Tampering**: Cryptographic `update_digest` binding between `begin`, `miller`, and `finish` stages (`MosooError::JobDigestMismatch`).
12. **Historical Block Root Forgery**: Authentication of historical blocks against the `BeaconState.block_roots` accumulator vector at generalized index 37.

---

## 4. Verification Evidence & Test Suite Breakdown

The repository test suite consists of **147 automated tests** (144 unit/integration + 3 doc tests) passing with 0 warnings:

| Subsystem / Test Suite | Test File | Test Count | Scope Covered |
| :--- | :--- | :---: | :--- |
| **Core Verification & Crypto** | `mosoo-core/src/` | 33 (32 unit + 1 doc) | BLS pairing, fork domains, branch verification, MPT account & receipt decoding |
| **Adversarial Mutation Suite** | `tests/adversarial_mutation_tests.rs` | 24 | 24 explicit attack scenarios tested against guest handlers |
| **Light Client Suite** | `tests/light_client_tests.rs` | 21 | Canonical Period 1884 vector, bootstrap, multi-network domains |
| **Two-Way Bridge Suite** | `tests/two_way_bridge_tests.rs` | 2 | End-to-end Ethereum MosooLocker deposit, mETH mint, transfer, burn, and unlock |
| **LEZ v0.4 Acceptance Suite** | `tests/lez_v04_acceptance_tests.rs` | 4 | Single-tx gas envelopes (<=10M), PDA seeds, CPI dispatch, Core proxy routing |
| **Privacy & Zero-Correlation** | `tests/privacy_and_correlation_tests.rs` | 5 | Address shielding, unlinkability, byte-level state-diff inspection |
| **Reference Consumer (ERC-20)** | `consumers/erc20-receiver/src/lib.rs` | 20 (19 unit + 1 doc) | Atomic same-tx claims, receipt log proofs, replay rejection, parameter checks |
| **Reference Consumer & mETH Ledger** | `consumers/ether-receiver/src/lib.rs` | 27 (26 unit + 1 doc) | Native balance proofs, mETH token mint/burn/transfer ledger, BurnReceipt generation |
| **Sequencer E2E Suite** | `tests/sequencer_e2e_tests.rs` | 2 | Full 3-Tx lifecycle on mock sequencer across Mainnet and Sepolia |
| **Consumer Lifecycle E2E** | `tests/e2e_consumer_tests.rs` | 2 | Cross-slot nullifier persistence and end-to-end claim execution |
| **Daemon Operational Suite** | `daemon/src/main.rs` | 6 | Beacon parsing, randomized jitter, competing-update recovery, proxy URL derivations |
| **CLI Suite** | `cli/src/main.rs` | 1 | CLI argument parser and test vector loading |
| **Two-Way Bridge Testnet Pipeline** | `scripts/testnet-two-way-bridge.py` | 1 script (5 phases) | Live testnet sequencer connectivity, deposit, 3-tx split, mint, burn, unlock |
| **Evidence Verification Script** | `scripts/verify-evidence.py` | 1 script (12 checks) | Verifies committed sequencer harness execution manifests and tx receipts |
| **Live Testnet Verifier Script** | `scripts/verify-onchain.py` | 1 script (3 checks) | Verifies live testnet sequencer blocks, gas engine, and 10M limit |

---

## 5. Development Roadmap & Independent Security Audit

- **Milestone M0 (Current — Pre-grant Foundation)**: Complete cryptographic engine, 3-transaction split pipeline, MPT provers, canonical Ethereum `MosooLocker.sol` contract, `mETH` token and burn ledger, dual reference consumers with atomic same-transaction verification, 147 passing tests, reproducibility scripts, live testnet pipeline, and empirical benchmarks.
- **Milestone M1 (Public LEZ v0.4 Devnet Deployment)**: Deploy module to Logos Execution Zone public devnet upon v0.4 release; track live Sepolia/Mainnet beacon heads; deploy consumer dApps.
- **Milestone M2 (Logos Core Module Catalog & SPEL Integration)**: Register module into official Logos Core module catalog; finalize SPEL IDL interface; extend predicate operations.
- **Milestone M3 (Daemon Production Hardening)**: Multi-RPC failover with weighted endpoints, automated re-org handling, and Prometheus observability metrics.
- **Milestone M4 (Independent Security Audit)**: Formal security audit engagement with a recognized external security firm (\$10,000 budget / 3-week window), addressing formal verification, side-channel analysis, and final audit publication.
