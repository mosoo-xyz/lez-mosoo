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

### Pattern B: Decoupled Relayer Flow (Experimental — Non-Normative)

> [!WARNING]
> **Experimental Decoupled Workflow (Non-Normative):**
> Pattern B is provided strictly as an experimental decoupled / caching workflow. It must **not** be used for application actions that require RFP-021 atomic compliance.
> Under RFP-021 Functionality #7, all protected consumer actions **must** execute inclusion proof verification and dynamic predicate evaluation directly inside the consuming transaction (Pattern A). Any protected consumer action must independently verify the authenticated inclusion proof and evaluate the predicate inside the consuming transaction rather than blindly relying on previously recorded state.

For architectures where an off-chain relayer prepares intermediate state attestations, Mosoo defines a decoupled `VerifiedStatement` representation. However, production contracts must independently re-verify proofs within their own transaction boundary.

---

## 2. Recommended Consumer Pattern (RFP-021 Mandatory Standard)

For all production LEZ smart contracts consuming Mosoo attestations, the **Recommended Consumer Pattern** requires adherence to six mandatory security rules:

### 1. Expected Chain ID Validation
The consumer contract must explicitly assert that `statement.chain_id == EXPECTED_CHAIN_ID` (RFP-021 Functionality #5). This prevents cross-chain replay between Ethereum Mainnet, Sepolia, and other consensus networks.

### 2. Authenticated Instance Validation
The consumer must verify that the attesting `InstanceAccount` PDA matches the authorized Mosoo light client deployment (`account.address == expected_instance_pda`), preventing rogue or spoofed light-client instances from injecting unanchored state. The legacy zero-instance PDA path is strictly an offline compatibility fallback (V1) and must be rejected in production.

### 3. Canonical Statement ID and Nullifier
Consumers must derive replay nullifiers as deterministic PDAs using the Functionality #6 Statement ID:
`PDA([b"nullifier", statement.statement_id])`
Because the Statement ID binds `chain_id`, `genesis_validators_root`, `subject_key`, `proof_type_tag`, and `verified_value`, duplicate claims within the same transaction or across blocks are deterministically rejected.

### 4. Explicit Typed Error Handling
The consumer must map and handle every `MosooError` variant cleanly:
- `HeaderNotFinalized`: Defer execution until consensus finalization.
- `InvalidMerkleProof`: Reject malicious or corrupted proof calldata.
- `StaleSlot`: Reject headers older than the consumer's maximum allowed latency.
- `SubthresholdQuorum`: Reject headers without 2/3 sync committee approval (>= 342 signatures).
- `InvalidSignature`: Reject invalid BLS consensus signatures.
- `EventLogNotFound`: Reject execution if expected receipt log is absent.
- `PredicateFailed`: Reject state transitions if dynamic condition evaluates to false.
No error may be silently ignored.

### 5. Atomic Same-Transaction Verification
In accordance with RFP-021 Functionality #7 and Performance #1, proof verification and state change must execute within the same LEZ transaction boundary. If the proof is invalid or attestation fails, the entire transaction reverts, ensuring atomic execution without orphan state.

### 6. Fail-Closed Behaviour
Under no circumstances may a consumer fall back to unverified off-chain feeds, optimistic multi-sig assertions, or unauthenticated default values. If consensus state is missing, stale, or verification fails, the consuming transaction must unconditionally revert. Contracts must never fall back to default, unauthenticated, or optimistic assumptions when verified state is absent.

```rust
// Recommended Consumer Verification Pattern for LEZ dApps
pub fn verify_and_consume(
    ctx: Context<ConsumeAttestation>,
    proof: StateInclusionProof,
    predicate: Predicate,
) -> Result<()> {
    // 1. Verify the expected chain identity
    require_eq!(
        proof.chain_id,
        EXPECTED_CHAIN_ID,
        MosooConsumerError::MismatchedChainId
    );

    // 2. Verify the authenticated light-client instance
    require_eq!(
        ctx.accounts.mosoo_instance.key(),
        EXPECTED_MOSOO_INSTANCE,
        MosooConsumerError::UnauthorizedInstance
    );

    // 3. Execute atomic same-transaction CPI into Mosoo verifier (In-guest verification)
    let statement: VerifiedStatement = mosoo_cpi::verify_statement(
        ctx.accounts.mosoo_program.to_account_info(),
        &proof,
        &predicate,
    )?;

    // 4. Never accept an unverified fallback statement & fail closed if predicate fails
    require!(
        statement.predicate_holds,
        MosooConsumerError::PredicateEvaluationFailed
    );

    // 5. Enforce nullifier uniqueness via Statement ID
    let nullifier_seeds = &[
        b"nullifier",
        statement.statement_id.as_ref(),
    ];
    let (nullifier_pda, _bump) = Pubkey::find_program_address(nullifier_seeds, ctx.program_id);
    require!(
        ctx.accounts.nullifier_account.key() == nullifier_pda,
        MosooConsumerError::InvalidNullifierAddress
    );
    require!(
        !ctx.accounts.nullifier_account.is_spent,
        MosooConsumerError::NullifierAlreadySpent
    );
    ctx.accounts.nullifier_account.is_spent = true;

    // 6. Execute authorized consumer action
    ctx.accounts.execute_authorized_action(&statement)?;
    Ok(())
}
```

---

## 3. Consumer 1: ERC-20 Receiver (`consumers/erc20-receiver`)

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
    historical_execution_proof: None, // Or historical execution header + payload proof
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

## 4. Consumer 2: Native Ether Receiver (`consumers/ether-receiver`)

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
    historical_execution_proof: None,
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

## 5. Replay Protection & On-Chain State Model

### Deterministic Statement ID & Nullifier Derivation

Mosoo derives `statement_id` deterministically strictly from verified Ethereum state facts (`derive_statement_id_v2`, see ADR-008):

```text
// V2 Canonical Statement ID (invariant to predicate variations to prevent replay bypass):
statement_id = sha256("mosoo_statement_v2" || chain_id || genesis_validators_root || subject_key || proof_type_tag || verified_value)
```

For event logs, `subject_key` incorporates:

```text
subject_key = sha256("mosoo_receipt_log_v1" || execution_block_hash || slot || tx_index || log_index || emitter || topic0)
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

### Host Runtime Account Ownership & CPI Provenance Verification

To prevent attackers from passing caller-spoofed `StatementAccount` structs in decoupled relayer architectures, LEZ smart contracts enforce runtime-level account ownership:
1. **Host-Level Account Ownership (`RuntimeAccount`):** During Cross-Program Invocation (CPI) or account loading, the LEZ sequencer asserts that the statement account is strictly owned by `MOSOO_PROGRAM_ID` (`account.owner == MOSOO_PROGRAM_ID`).
2. **Canonical PDA Derivation:** The consumer re-derives `derive_statement_pda(chain_id, statement_id)` and verifies that `account.address == expected_pda`.
3. **Decoupled Relayer Invocations:** Consuming contracts utilize `mint_deposit_runtime_account_u256` or `claim_authenticated_runtime_account_u256` to validate host-provided runtime metadata rather than relying solely on caller-provided unauthenticated fields.
4. **Administrative Configuration Guarding:** Bridge configuration mutators `register_trusted_locker_authorized` and `allow_token_authorized` strictly enforce administrative key authorization before any locker or token whitelist alterations are committed to state.

---

## Appendix: Experimental Two-Way Settlement Prototype (Out of Scope for RFP-021)

> **RFP-021 Grant Scope Notice:** Logos RFP-021 strictly covers inbound trustless Ethereum state attestation into LEZ. Application-specific minting, escrow, settlement, and reverse LEZ-to-Ethereum token bridging are explicitly outside the funded grant scope. The prototype below is provided solely as an experimental architectural appendix demonstrating how external applications can build on top of Mosoo's attestation primitive.

In addition to one-way state attestations, Mosoo provides an experimental **Two-Way Cross-Chain Token Bridge** maintaining strict cross-chain supply invariance:

$$\text{Locked on Ethereum Escrow} \equiv \text{Active Supply on LEZ}$$

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Two-Way Token Bridge Flow                          │
│                                                                             │
│  [Ethereum EVM]                                    [Logos LEZ]              │
│  MosooLocker.sol                                   Consumers / Ledgers      │
│                                                                             │
│  depositETH(lezRecipient)  ──(Light Client MPT)──► mint_meth() (1:1 mETH)   │
│  depositShieldedETH(commitment) [hardened v3 live on Sepolia 0x374B9F07...]│
│                                                          │                  │
│                                                          ▼                  │
│                                                  transfer_meth() (LEZ P2P)  │
│                                                          │                  │
│                                                          ▼                  │
│  unlockETH* / v2 unlockShieldedETH ◄──(Burn)──── burn_meth()                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Native ETH Wrapped Ledger (`MethLedger`)

The `MethLedger` in `consumers/ether-receiver` maintains state accounts for wrapped ether (`mETH`):

```rust
use ether_receiver::{MethLedger, NativeEthDepositClaim, EtherNullifierSet};

let mut ledger = MethLedger::new();
let mut nullifiers = EtherNullifierSet::new();

// 1. Mint mETH on LEZ upon verified Ethereum deposit
let minted_wei = ledger.mint_from_deposit(&deposit_claim, &mut nullifiers)
    .expect("Deposit mint succeeded");

// 2. Transfer mETH between LEZ accounts
ledger.transfer_meth(&alice_lez, &bob_lez, 2_000_000_000_000_000_000)
    .expect("Transfer succeeded");

// 3. Burn mETH on LEZ to unlock native ETH on Ethereum
let burn_receipt = ledger.burn_meth(
    ETH_MAINNET_CHAIN_ID,
    &bob_lez,
    2_000_000_000_000_000_000, // 2 ETH
    &eth_recipient_address,
    current_lez_slot,
).expect("Burn succeeded");
```

### 5.2 ERC-20 Wrapped Ledger (`Erc20Ledger`)

The `Erc20Ledger` in `consumers/erc20-receiver` supports arbitrary ERC-20 tokens (e.g., USDC, USDT, DAI):

```rust
use erc20_receiver::{Erc20Ledger, Erc20TransferClaim, NullifierSet};

let mut ledger = Erc20Ledger::new();
let mut nullifiers = NullifierSet::new();

// 1. Mint wrapped ERC-20 on LEZ upon verified Ethereum transfer
let minted_tokens = ledger.mint_tokens(&transfer_claim, &mut nullifiers)
    .expect("Token mint succeeded");

// 2. Peer-to-peer transfer on LEZ
ledger.transfer_tokens(&token_contract, &alice_lez, &bob_lez, 500_000_000)
    .expect("Transfer succeeded");

// 3. Burn wrapped tokens on LEZ to unlock on Ethereum
let burn_receipt = ledger.burn_tokens(
    ETH_MAINNET_CHAIN_ID,
    &token_contract,
    &bob_lez,
    500_000_000,
    &eth_recipient_address,
    current_lez_slot,
).expect("Burn succeeded");
```

### 5.3 Cryptographic Burn ID & Ethereum Unlock (`MosooLocker.sol`)

The `BurnReceipt` derives a collision-resistant 32-byte identifier using exact cryptographic byte-alignment with Solidity's `keccak256(abi.encodePacked(...))`:

- **Native ETH (`derive_burn_id` / 145 bytes packed):**
  ```text
  keccak256(
    "mosoo_burn_v1" || chain_id (uint256) || lez_owner (bytes32) ||
    eth_recipient (address) || amount_wei (uint256) || burn_nonce (uint64) || lez_slot (uint64)
  )
  ```
- **ERC-20 (`derive_burn_erc20_id` / 171 bytes packed):**
  ```text
  keccak256(
    "mosoo_burn_erc20_v1" || chain_id (uint256) || token_contract (address) ||
    lez_owner (bytes32) || eth_recipient (address) || amount (uint256) ||
    burn_nonce (uint64) || lez_slot (uint64)
  )
  ```

On the Ethereum EVM side, `MosooLocker.sol` verifies the attested burn and releases escrowed funds:

```solidity
// Native ETH Unlock
function unlockETH(
    bytes32 burnId,
    bytes32 lezBurner,
    address payable recipient,
    uint256 amountWei,
    uint64 burnNonce,
    uint64 lezSlot,
    bytes calldata signature
) external nonReentrant;

// ERC-20 Unlock
function unlockERC20(
    bytes32 burnId,
    address token,
    bytes32 lezBurner,
    address recipient,
    uint256 amount,
    uint64 burnNonce,
    uint64 lezSlot,
    bytes calldata signature
) external nonReentrant;
```

**Security Guarantees on Ethereum:**
- **Replay Protection:** `executedBurns[burnId]` records every processed burn (plus `cancelledBurns[burnId]` for Guardian-vetoed burns); duplicates revert immediately with `BurnAlreadyExecuted()` / `BurnCancelled()`.
- **EIP-2 Malleability Defense:** Signatures enforce strict upper bound on $s$ ($s \le \text{0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0}$) and reject `address(0)` recovered signers.
- **Fee-on-Transfer Protection:** Balance differential pattern on ERC-20 deposits (`depositERC20` / local v2 `depositShieldedERC20`) ensures only actual tokens received are credited.
- **Two-Step Ownership:** Contract ownership changes require `transferOwnership` followed by `acceptOwnership`.
- **Hardened Shielded Pool v3 (Live Commissioned on Sepolia):** [`contracts/MosooLocker.sol`](../contracts/MosooLocker.sol) v3 (`0x374B9F073A6aC1aF2c147392319499e35E8C7e82`, `productionCommissioned = true` `2-of-2` latch, `shieldedDepositsOnly = true`, `strictFixedDenominationMode = true`, `legacyRoutesPermanentlyDisabled = true`) is live on Sepolia with verified `DepositCommitted` (`0x3ceb8bc3...` / `0xef24568c...`) and `UnlockedShieldedETH` (`0x3204263c...`) transactions (historical v1 `0x7462...` & v2 `0xEFEf...` preserved in `contracts/deployments/sepolia.json`).
