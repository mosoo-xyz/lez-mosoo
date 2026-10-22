# Mosoo Reference Consumers Guide

This document provides developer integration guides and code examples for consuming verified Ethereum state attestations within Logos Execution Zone (LEZ) smart contracts.

Mosoo provides **two reference consumer implementations** satisfying RFP-021:
1. `erc20-receiver`: Trustless token minting from verified Ethereum ERC-20 transfers & event logs.
2. `ether-receiver`: Trustless native ETH balance accounting and crediting.

---

## 1. Consumer Integration Models

Logos RFP-021 specifies that state inclusion verification and predicate evaluation must occur in the consuming transaction to prevent reliance on forged or unauthenticated out-of-band statements. Mosoo supports two consumer design patterns:

### Pattern A: Atomic Same-Transaction Verification (Primary — RFP-021 Functionality #7)

In this pattern, the consuming transaction directly executes state verification against an authenticated `HeaderRecord` committed by the Mosoo light client. Verification and token minting execute atomically in a single LEZ transaction.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Consuming Transaction (Atomic)                        │
│                                                                             │
│  1. Read authenticated HeaderRecord from Mosoo instance PDA                 │
│  2. Execute in-guest MPT proof verification (verify_state_proof)            │
│  3. Evaluate condition predicate (Predicate::AtLeast, Equal, etc.)          │
│  4. Assert parameter binding (token_contract, recipient, slot/emitter)      │
│  5. Check & create nullifier PDA (seeds = [b"nullifier", statement_id])     │
│  6. Execute authorized action (mint tokens / credit ether)                  │
│                                                                             │
│  * If ANY step fails (bad proof, bad header, failed predicate), the entire  │
│    transaction REVERTS atomically. No forged statements can be accepted.    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Pattern B: Decoupled Relayer Flow (Secondary — Asynchronous Pipeline)

For architectures where a relayer submits state attestations prior to user claims, Mosoo's attestation module emits a deterministic `VerifiedStatement`. The consumer verifies the statement's provenance, matches parameters against `StatementBinding`, checks the nullifier, and mints tokens.

---

## 2. Consumer 1: ERC-20 Receiver (`consumers/erc20-receiver`)

### Pattern A: Atomic Same-Transaction Claim (`claim_atomic`)

The consumer accepts the light client instance, header record, MPT proof (receipt log or contract storage slot), predicate, and claim parameters in a single transaction:

```rust
use erc20_receiver::{claim_atomic, AtomicErc20ClaimArgs, NullifierSet};
use mosoo_core::inclusion::StateProof;
use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate};

let mut nullifiers = NullifierSet::new();

let args = AtomicErc20ClaimArgs {
    instance: light_client_instance,
    header: authenticated_header_record,
    header_history_branch: None, // Or historical block roots branch
    proof: state_inclusion_proof, // MPT proof for receipt log or storage slot
    predicate: Predicate::AtLeast { min: min_amount_32 },
    expected_token_contract: [0xaa; 20], // ERC-20 token contract on Ethereum
    expected_sender: None, // Optional depositor address
    recipient: [0x33; 32], // Beneficiary LEZ account
    min_amount: 1_000_000,
};

// Verifies MPT proof in-transaction, evaluates predicate, marks nullifier, and mints
let minted = claim_atomic(args, &mut nullifiers)
    .expect("Atomic proof verification and claim succeeded");
```

### Pattern B: Decoupled Statement Claim (`claim_erc20_transfer`)

For asynchronous relayer pipelines where `attest_state` has already been confirmed:

```rust
use erc20_receiver::{claim_erc20_transfer, Erc20TransferClaim, NullifierSet};

let mut nullifiers = NullifierSet::new();

let claim = Erc20TransferClaim {
    statement: verified_statement,
    token_contract: [0x11; 20],
    sender: [0x22; 20],
    recipient: [0x33; 32],
    min_amount: 100_000,
};

let minted = claim_erc20_transfer(&claim, &mut nullifiers)
    .expect("Valid ERC-20 transfer claim succeeds");
```

---

## 3. Consumer 2: Native Ether Receiver (`consumers/ether-receiver`)

### Pattern A: Atomic Same-Transaction Claim (`claim_ether_atomic`)

Directly proves Ethereum native balance from the account state trie and credits LEZ ether in one atomic step:

```rust
use ether_receiver::{claim_ether_atomic, AtomicEtherClaimArgs, EtherNullifierSet};
use mosoo_core::inclusion::StateProof;
use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate};

let mut nullifiers = EtherNullifierSet::new();

let args = AtomicEtherClaimArgs {
    instance: light_client_instance,
    header: authenticated_header_record,
    header_history_branch: None,
    proof: account_balance_proof, // MPT proof from eth_getProof
    predicate: Predicate::AtLeast { min: min_wei_32 },
    expected_address: [0x42; 20], // Ethereum account / vault
    recipient: [0x33; 32],        // LEZ recipient
    min_wei: 1_000_000_000_000_000_000, // 1 ETH
};

let credited = claim_ether_atomic(args, &mut nullifiers)
    .expect("Atomic ether claim succeeded");
```

### Pattern B: Decoupled Statement Claim (`claim_native_eth_deposit`)

```rust
use ether_receiver::{claim_native_eth_deposit, EtherNullifierSet, NativeEthDepositClaim};

let mut nullifiers = EtherNullifierSet::new();

let deposit_claim = NativeEthDepositClaim {
    statement: verified_statement,
    expected_deposit_contract: [0xaa; 20],
    sender: [0xbb; 20],
    recipient: [0xcc; 32],
    min_wei: 1_000_000_000_000_000_000,
};

let credited = claim_native_eth_deposit(&deposit_claim, &mut nullifiers)
    .expect("Valid native ETH deposit claim succeeds");
```

---

## 4. Replay Protection & On-Chain State Model

### Deterministic Statement ID & Nullifier Derivation

Mosoo derives `statement_id` deterministically from verified consensus and state data:

```text
statement_id = sha256(chain_id || subject_key || proof_type || value || predicate)
```

For event logs, `subject_key` incorporates:

```text
subject_key = block_hash || slot || tx_index || log_index || emitter || topic0
```

This guarantees that identical deposits in different transactions or blocks never collide and cannot be replayed.

### LEZ PDA Enforcement vs Local Harness

In local testing and simulation, nullifiers are stored in `NullifierSet` / `EtherNullifierSet` backed by an in-memory hash set.

On the live Logos Execution Zone runtime:
- Nullifiers are enforced as Program Derived Addresses (PDAs):
  ```text
  pda = find_program_address(&[b"nullifier", statement_id], program_id)
  ```
- When a claim transaction executes, LEZ attempts to initialize the PDA account.
- If the account already exists (indicating a prior claim), the LEZ transaction runtime aborts with an account collision error, preventing replay at the consensus layer before any token minting instruction executes.
