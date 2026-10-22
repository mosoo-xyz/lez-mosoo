# Smart Policy Execution Language (SPEL) IDL Specification

This document defines the canonical **SPEL IDL (Smart Policy Execution Language)** interface and Logos Core module specification for the **Mosoo Ethereum Consensus & State Attestation Module** (RFP-021).

---

## 1. Logos Core Module Architecture

Mosoo registers as a reusable system primitive within the Logos Execution Zone (LEZ). Basecamp applications, cross-chain DEXs, lending protocols, and sovereign communities invoke Mosoo via cross-program invocations (CPI) defined by this SPEL interface:

```
┌────────────────────────────────────────────────────────┐
│             Logos Core Module Catalog                  │
│                                                        │
│   ┌────────────────────────────────────────────────┐   │
│   │   mosoo_ethereum_attester (SPEL IDL v0.1.0)   │   │
│   └────────────────────────────────────────────────┘   │
└──────────────────────────┬─────────────────────────────┘
                           │ CPI Invocations
             ┌─────────────┴─────────────┐
             ▼                           ▼
    ┌─────────────────┐         ┌─────────────────┐
    │  erc20-receiver │         │  ether-receiver │
    │ (Token Minting) │         │ (Native Ether)  │
    └─────────────────┘         └─────────────────┘
```

---

## 2. Canonical SPEL IDL Declaration

```spel
module mosoo_ethereum_attester {
    version: "0.1.0"
    program_id: "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c"

    // Initial weak-subjectivity bootstrap
    method initialize(
        chain_id: u64,
        trusted_slot: u64,
        beacon_header_root: bytes32,
        sync_committee_branch: vector<bytes32>
    ) -> (instance_pda: address)
    gas_limit: 2000000;

    // 3-Tx BLS Split Stage 1: Quorum assertion & key aggregation
    method begin_update(
        instance_pda: address,
        update_payload: bytes
    ) -> (job_pda: address)
    gas_limit: 6000000;

    // 3-Tx BLS Split Stage 2: Dual Miller loops
    method miller_update(
        job_pda: address
    ) -> (stage: u8)
    gas_limit: 5000000;

    // 3-Tx BLS Split Stage 3: Final exponentiation & HeaderRecord write
    method finish_update(
        job_pda: address,
        execution_payload_header: bytes
    ) -> (header_record_pda: address)
    gas_limit: 4500000;

    // Cryptographic state & receipt log attestation
    method attest_state(
        header_record_pda: address,
        proof_payload: bytes,
        predicate_payload: bytes
    ) -> (statement: VerifiedStatement)
    gas_limit: 2000000;

    // Standard Error Codes
    errors {
        0x01: InsufficientParticipation "Less than 2/3 sync committee quorum (requires >= 342)"
        0x02: BlsVerificationFailed     "Aggregate BLS12-381 signature verification failed"
        0x03: StaleUpdate               "Submitted slot is <= current finalized slot"
        0x04: InvalidCommitteeBranch    "SSZ generalized index 54/55 Merkle proof failed"
        0x05: MissingExecutionPayload   "Update omitted execution payload header or gindex 25 branch"
        0x06: MptProofFailed            "Merkle-Patricia Trie proof failed verification"
        0x07: PredicateFailed           "Evaluated predicate condition returned false"
        0x08: NullifierAlreadySpent     "Statement nullifier has already been claimed (replay)"
        0x09: WeakSubjectivityExpired   "Update slot exceeds weak-subjectivity window (1,728,000 slots)"
        0x0A: UnauthenticatedHeader     "HeaderRecord not authenticated by instance's finalized beacon root"
        0x0B: DomainSeparationFailed    "Header chain_id does not match instance chain_id"
        0x0C: WrongJobStage             "Instruction called out of pipeline sequence (Begin→Miller→Finish)"
        0x0D: UnsupportedChain          "chain_id is not a supported Ethereum network"
    }
}
```

---

## 3. Supported Network Configuration

Mosoo supports all major Ethereum networks with complete fork schedules:

| Network | Chain ID | Fork Coverage | Notes |
| :--- | :---: | :--- | :--- |
| **Ethereum Mainnet** | `1` | Altair → Bellatrix → Capella → Deneb → Electra → **Fulu** | Active through slot 13,164,544+ |
| **Sepolia Testnet** | `11155111` | Altair → Capella → Deneb → Electra → **Gloas** | Gloas activated slot 7,077,888 (Oct 6, 2026) |
| **Hoodi Testnet** | `560048` | Fulu → **Gloas** | Gloas activating slot 786,432 (Oct 26, 2026) |
| **Holesky Testnet** | `17000` | Deneb → Electra → Fulu | Deprecated; supported for completeness |

Each network uses cryptographically distinct `genesis_validators_root` and per-slot `fork_version`, ensuring that BLS signatures from any one network are mathematically invalid when evaluated on another.

---

## 4. Rust Code Generation & Integration

The SPEL specification is programmatically defined in `mosoo-core/src/spel.rs`. Developers can export the complete JSON schema using:

```rust
use mosoo_core::spel::SpelModuleDefinition;

let schema = SpelModuleDefinition::canonical();
let json = serde_json::to_string_pretty(&schema).unwrap();
println!("{}", json);
```

Basecamp consumers invoke `attest_state` via standard CPI calls without handling underlying BLS or MPT cryptographic complexity.
