# ADR 003: Evaluation of Helios, revm-helios, and Prior Art

## Status
Accepted

## Context
Logos RFP-021 (*Trustless Ethereum State Attestation for LEZ*) explicitly requires teams to evaluate existing open-source Ethereum light-client implementations — specifically `helios` (a16z), `revm-helios`, and `spl-helios` — to determine whether they can be directly adopted, adapted, or if custom architectural choices are necessary.

This document records our technical evaluation of each implementation, the constraints imposed by the Logos Execution Zone (LEZ), and the architectural rationale for Mosoo's design.

---

## Evaluation of Existing Implementations

### 1. a16z/helios
**Overview:** Helios is a Rust-based, trustless Ethereum light client that syncs Altair sync committee headers and proves account state and storage slots via `eth_getProof`.

**Analysis for LEZ:**
- **Monolithic BLS Verification:** Helios evaluates sync-committee BLS12-381 aggregate signatures in a single function call. On native x86/ARM hardware, this takes a few milliseconds. However, inside a RISC Zero zkVM guest without host-level precompiles, this single pairing operation requires ~13.3M gas, exceeding LEZ's per-transaction gas limit of 10,000,000 gas.
- **Runtime & Dependency Footprint:** Helios relies on Tokio async networking, hyper/reqwest HTTP clients, and standard library I/O. These dependencies cannot compile into the constrained `riscv32im-risc0-zkvm-elf` target without massive cycle inflation.
- **No SPEL or PDA Integration:** Helios has no native concept of the Logos Smart Policy Execution Language (SPEL), Program Derived Addresses (PDAs), or cross-program invocation (CPI).

**Mosoo Reuse Strategy:**
Rather than vendoring the entire Helios binary, we adopted Helios's consensus verification models, generalized index definitions, and SSZ container structures. We ported them into a zero-allocation, `no-std` compatible core (`mosoo-core`) and replaced the monolithic BLS check with our 3-transaction pipeline.

---

### 2. revm-helios
**Overview:** Combines Helios's light-client state verification with `revm` (the Rust Ethereum Virtual Machine) to execute EVM bytecode client-side against verified state roots.

**Analysis for LEZ:**
- **Mismatched Scope:** RFP-021 focuses on *state attestation* — allowing LEZ smart contracts to verify Ethereum facts (balances, storage values, event logs) on-chain. It does not require re-executing Ethereum transactions inside LEZ.
- **Execution Overhead:** Running `revm` inside RISC Zero to re-execute EVM transactions would add millions of unnecessary compute cycles and gas. Ethereum transactions are already executed and finalized on Ethereum; LEZ only needs to verify their cryptographic inclusion in finalized state or receipt tries.

**Mosoo Reuse Strategy:**
Instead of running a full EVM emulator, Mosoo uses direct Merkle-Patricia Trie (MPT) inclusion proofs via `alloy-trie` against finalized execution roots (`state_root` and `receipts_root`). This verifies account balances, storage slots, and EIP-2718 event logs with minimal cycles (< 3M cycles) and zero EVM emulation overhead.

---

### 3. spl-helios (Solana Light Client Port)
**Overview:** An adaptation of Helios designed to run as an on-chain program on Solana (eBPF runtime).

**Analysis for LEZ:**
- **Host Precompile Dependency:** Solana exposes a native host syscall (`sol_bls12381`) that executes BLS12-381 operations outside the eBPF VM, allowing `spl-helios` to verify updates in a single transaction. In contrast, LEZ does not currently offer a native BLS12-381 host precompile, and adding host precompiles was explicitly designated out-of-scope in RFP-021.
- **Runtime Environment:** `spl-helios` targets Solana's eBPF VM, whereas LEZ targets RISC Zero zkVM (`riscv32im-risc0-zkvm-elf`). Memory models, syscall interfaces, and execution constraints differ significantly.

**Mosoo Reuse Strategy:**
`spl-helios` demonstrates the viability of on-chain light client verification, but its reliance on Solana-specific host precompiles makes direct reuse on LEZ impossible. Mosoo's 3-transaction BLS split is specifically designed to solve this exact problem on LEZ without host VM modifications.

---

## Architectural Comparison

| Dimension | a16z/helios | revm-helios | spl-helios | Mosoo (RFP-021) |
| :--- | :--- | :--- | :--- | :--- |
| **Execution Environment** | Native CLI / Host CPU | Native CLI + EVM | Solana eBPF | RISC0 zkVM (LEZ Guest) |
| **LEZ Gas Cap Compliance** | N/A (Exceeds 10M in zkVM) | N/A (Exceeds 10M) | N/A (Requires Solana host) | **Strict 3-Tx Split (< 5.4M Gas)** |
| **Host Precompile Dependency** | No (Native CPU) | No (Native CPU) | **Yes (`sol_bls12381`)** | **Zero host precompiles required** |
| **Ethereum Fork Support** | Deneb | Deneb | Capella / Deneb | **Deneb, Electra, Fulu, Gloas** |
| **State Prover** | MPT via RPC | Full EVM Re-execution | MPT Proofs | **alloy-trie MPT (State & Receipts)** |
| **Logos SPEL Integration** | None | None | None | **Native SPEL IDL & PDA Model** |
| **Replay Protection** | Client-side only | Client-side only | Account-based | **Deterministic Nullifiers** |

---

## Conclusion
Direct reuse of `helios`, `revm-helios`, or `spl-helios` as-is is not feasible for LEZ due to gas limits, zkVM constraints, and runtime differences. 

Mosoo incorporates the proven cryptographic formulas of Helios and the MPT traversal patterns of `alloy-trie`, while introducing the novel 3-transaction split and SPEL PDA architecture required for production deployment on the Logos Execution Zone.
