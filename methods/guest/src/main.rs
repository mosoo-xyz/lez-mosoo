//! Mosoo LEZ guest program — Ethereum light-client attestation module.
//!
//! This program runs inside the **RISC0 zkVM** on the Logos Execution Zone.
//! It exposes four SPEL instructions that together implement trustless
//! Ethereum state attestation:
//!
//! 1. [`initialize`]  — bootstrap an instance for a specific Ethereum chain.
//! 2. [`begin_update`]  — Tx 1 of the BLS verification (≈ 5.4 M gas).
//! 3. [`miller_update`] — Tx 2 of the BLS verification (≈ 4.2 M gas).
//! 4. [`finish_update`] — Tx 3 of the BLS verification + state write (≈ 3.8 M gas).
//!
//! Consumer programs can then call [`attest_state`] to verify an Ethereum
//! state-inclusion proof against an authenticated `HeaderRecord` and receive a
//! `VerifiedStatement` nullifier.
//!
//! ## Why three transactions?
//!
//! A full BLS12-381 aggregate signature verification requires ≈ 13.4 M RISC0
//! cycles, which exceeds the LEZ single-transaction gas cap of ~10 M.
//! Splitting across Begin -> Miller -> Finish keeps each transaction under the
//! cap while maintaining atomicity of the security guarantee (an invalid
//! signature is rejected at Finish).

#![no_main]

use mosoo_core::{
    error::MosooError,
    verifier::{dispatch_guest_instruction, GuestInstruction, InstructionOutput},
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub type Instruction = GuestInstruction;

fn main() {
    // The host encodes a tagged instruction envelope.
    // In production LEZ blockchain transactions, SPEL smart contract instructions execute
    // natively in the LEZ host runtime via `dispatch_store_instruction(&mut host_store, instruction)`
    // with authentic persistent RocksDB/state trie storage, loading accounts owned by MOSOO_PROGRAM_ID.
    // When executing inside RISC0 zkVM, instructions deserialize from `env::read()` and are
    // processed via `dispatch_guest_instruction(instruction)`. Authenticated instruction variants
    // (AttestStateAuthenticated, BeginUpdateAuthenticated, etc.) strictly enforce canonical instance
    // PDA binding, pinned checkpoint anchors, and verified RuntimeAccount witnesses.
    let instruction: Instruction = env::read();

    let result: Result<InstructionOutput, MosooError> = dispatch_guest_instruction(instruction);

    // Privacy-preserving public journal emission (RFP-021 Functionality #8, Finding 4, & Finding 5 / Session 10 & 12):
    // Statements emitted to public zkVM journal are automatically shielded so that
    // Ethereum addresses, event logs, subject keys, and LEZ recipients are never exposed publicly.
    // In production privacy mode, caller supplies a 256-bit secret salt in AttestStateArgs, ensuring
    // non-correlation across repeated statements and immunity to dictionary matching.
    // If the statement is already salted-shielded, its blinding is preserved.
    // For private statement types (AccountBalance, StorageSlot, ReceiptLog), unshielded value leakage is rejected (Finding 5 / Session 12).
    let safe_result = result.and_then(|output| match output {
        InstructionOutput::StatementIssued(stmt) => {
            if (stmt.proof_type_tag == mosoo_core::types::PROOF_TYPE_ACCOUNT_BALANCE
                || stmt.proof_type_tag == mosoo_core::types::PROOF_TYPE_STORAGE_SLOT
                || stmt.proof_type_tag == mosoo_core::types::PROOF_TYPE_RECEIPT_LOG)
                && !stmt.is_value_shielded()
            {
                return Err(MosooError::InvalidBootstrap(
                    "private statement types (AccountBalance, StorageSlot, ReceiptLog) require confidential privacy shielding in zkVM public journal"
                        .into(),
                ));
            }
            if stmt.is_shielded() {
                Ok(InstructionOutput::StatementIssued(stmt))
            } else {
                Ok(InstructionOutput::StatementIssued(stmt.shield()))
            }
        }
        other => Ok(other),
    });

    // Commit the result to the journal (public outputs of the zkVM program).
    env::commit(&safe_result.map_err(|e| e.to_string()));
}
