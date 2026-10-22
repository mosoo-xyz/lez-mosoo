//! mosoo-core — shared types for the Mosoo Ethereum attestation module.
//!
//! This crate is compiled for both the **RISC0 guest** (zkVM) and the **host**
//! (daemon, CLI, tests). Keep it `no_std`-compatible where possible so the
//! guest image stays small.

pub mod crypto;
pub mod error;
pub mod inclusion;
pub mod predicate;
pub mod spel;
pub mod types;
pub mod verifier;

pub use error::MosooError;
pub use types::*;
pub use verifier::*;
