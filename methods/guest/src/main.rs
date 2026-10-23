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
    types::*,
    verifier::{
        handle_attest_state, handle_begin_update, handle_finish_update, handle_initialize,
        handle_miller_update, handle_recover_instance, AttestStateArgs, BeginUpdateArgs,
        FinishUpdateArgs, InstructionOutput, MillerUpdateArgs,
    },
};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
enum Instruction {
    Initialize(InitializeArgs),
    RecoverInstance(RecoverInstanceArgs),
    BeginUpdate(BeginUpdateArgs),
    MillerUpdate(MillerUpdateArgs),
    FinishUpdate(FinishUpdateArgs),
    AttestState(AttestStateArgs),
}

fn main() {
    // The host encodes a tagged instruction envelope.
    let instruction: Instruction = env::read();

    let result: Result<InstructionOutput, MosooError> = match instruction {
        Instruction::Initialize(args) => handle_initialize(args),
        Instruction::RecoverInstance(args) => handle_recover_instance(args),
        Instruction::BeginUpdate(args) => handle_begin_update(args),
        Instruction::MillerUpdate(args) => handle_miller_update(args),
        Instruction::FinishUpdate(args) => handle_finish_update(args),
        Instruction::AttestState(args) => handle_attest_state(args),
    };

    // Commit the result to the journal (public outputs of the zkVM program).
    env::commit(&result.map_err(|e| e.to_string()));
}
