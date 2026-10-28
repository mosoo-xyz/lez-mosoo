//! Smart Policy Execution Language (SPEL) IDL Definitions for Logos Core
//!
//! Provides canonical interface declarations, type specifications, error code mappings,
//! and invocation schemas for integrating Mosoo into the Logos Core Module Catalog (RFP-021).

use serde::{Deserialize, Serialize};

/// Canonical data types supported in the Logos SPEL IDL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpelType {
    Bool,
    U8,
    U64,
    U256,
    Bytes32,
    Bytes48,
    Bytes96,
    AccountAddress,
    ByteArray,
    Vector(Box<SpelType>),
    Option(Box<SpelType>),
    Custom(String),
}

/// Parameter definition for a SPEL method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpelParameter {
    pub name: String,
    pub spel_type: SpelType,
    pub description: String,
}

/// Method entrypoint definition in Logos SPEL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpelMethod {
    pub name: String,
    pub method_id: u32,
    pub gas_limit: u64,
    pub is_mutating: bool,
    pub inputs: Vec<SpelParameter>,
    pub outputs: Vec<SpelParameter>,
    pub description: String,
}

/// Standardized error code mapping in Logos Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpelErrorCode {
    pub code: u32,
    pub name: String,
    pub description: String,
}

/// Complete Logos Core module definition for Mosoo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpelModuleDefinition {
    pub module_name: String,
    pub version: String,
    pub author: String,
    pub program_id: String,
    pub methods: Vec<SpelMethod>,
    pub error_codes: Vec<SpelErrorCode>,
}

impl SpelModuleDefinition {
    /// Constructs the canonical SPEL specification for Mosoo Ethereum Attestation.
    pub fn canonical() -> Self {
        Self {
            module_name: "mosoo_ethereum_attester".to_string(),
            version: "0.1.0".to_string(),
            author: "Mosoo Contributors (Omkar Chavan)".to_string(),
            program_id: "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c".to_string(),
            methods: vec![
                SpelMethod {
                    name: "initialize".to_string(),
                    method_id: 0x00000001,
                    gas_limit: 2_000_000,
                    is_mutating: true,
                    inputs: vec![
                        SpelParameter {
                            name: "chain_id".to_string(),
                            spel_type: SpelType::U64,
                            description: "Target Ethereum chain ID (1 = Mainnet, 11155111 = Sepolia, 17000 = Holesky)".to_string(),
                        },
                        SpelParameter {
                            name: "trusted_slot".to_string(),
                            spel_type: SpelType::U64,
                            description: "Weak-subjectivity beacon slot".to_string(),
                        },
                        SpelParameter {
                            name: "beacon_header_root".to_string(),
                            spel_type: SpelType::Bytes32,
                            description: "SSZ hash tree root of the trusted beacon block header".to_string(),
                        },
                        SpelParameter {
                            name: "sync_committee_branch".to_string(),
                            spel_type: SpelType::Vector(Box::new(SpelType::Bytes32)),
                            description: "SSZ generalized index 54 Merkle proof for initial 512-validator sync committee".to_string(),
                        },
                    ],
                    outputs: vec![
                        SpelParameter {
                            name: "instance_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Address of the created InstanceAccount PDA".to_string(),
                        },
                    ],
                    description: "Initializes a new Ethereum light client instance from a trusted weak-subjectivity checkpoint".to_string(),
                },
                SpelMethod {
                    name: "begin_update".to_string(),
                    method_id: 0x00000002,
                    gas_limit: 6_000_000,
                    is_mutating: true,
                    inputs: vec![
                        SpelParameter {
                            name: "instance_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Address of target InstanceAccount".to_string(),
                        },
                        SpelParameter {
                            name: "update_payload".to_string(),
                            spel_type: SpelType::ByteArray,
                            description: "LightClientUpdate containing headers, quorum bits, and signature".to_string(),
                        },
                    ],
                    outputs: vec![
                        SpelParameter {
                            name: "job_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Temporary JobAccount PDA tracking the 3-transaction BLS pairing sequence".to_string(),
                        },
                    ],
                    description: "Step 1 of 3: Verifies quorum (>= 342) and aggregates active validator public keys".to_string(),
                },
                SpelMethod {
                    name: "miller_update".to_string(),
                    method_id: 0x00000003,
                    gas_limit: 5_000_000,
                    is_mutating: true,
                    inputs: vec![
                        SpelParameter {
                            name: "job_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Address of the active JobAccount".to_string(),
                        },
                    ],
                    outputs: vec![
                        SpelParameter {
                            name: "stage".to_string(),
                            spel_type: SpelType::U8,
                            description: "Updated progression stage (2 = MillerComplete)".to_string(),
                        },
                    ],
                    description: "Step 2 of 3: Computes dual Miller loops e(sig, G1) * e(msg, agg_pk)^-1".to_string(),
                },
                SpelMethod {
                    name: "finish_update".to_string(),
                    method_id: 0x00000004,
                    gas_limit: 4_500_000,
                    is_mutating: true,
                    inputs: vec![
                        SpelParameter {
                            name: "job_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Address of the active JobAccount".to_string(),
                        },
                        SpelParameter {
                            name: "execution_payload_header".to_string(),
                            spel_type: SpelType::ByteArray,
                            description: "Execution payload header verified against beacon body_root (gindex 25)".to_string(),
                        },
                    ],
                    outputs: vec![
                        SpelParameter {
                            name: "header_record_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Permanent HeaderRecord PDA containing authenticated execution state & receipts roots".to_string(),
                        },
                    ],
                    description: "Step 3 of 3: Final exponentiation in F_p^12, verifies gindex 25 payload, and commits HeaderRecord".to_string(),
                },
                SpelMethod {
                    name: "attest_state".to_string(),
                    method_id: 0x00000005,
                    gas_limit: 2_000_000,
                    is_mutating: false,
                    inputs: vec![
                        SpelParameter {
                            name: "header_record_pda".to_string(),
                            spel_type: SpelType::AccountAddress,
                            description: "Target authenticated HeaderRecord".to_string(),
                        },
                        SpelParameter {
                            name: "proof_payload".to_string(),
                            spel_type: SpelType::ByteArray,
                            description: "MPT state proof (account, storage, or receipt log)".to_string(),
                        },
                        SpelParameter {
                            name: "predicate_payload".to_string(),
                            spel_type: SpelType::ByteArray,
                            description: "Predicate condition (Equal, AtLeast, All, Any)".to_string(),
                        },
                    ],
                    outputs: vec![
                        SpelParameter {
                            name: "verified_statement".to_string(),
                            spel_type: SpelType::Custom("VerifiedStatement".to_string()),
                            description: "Collision-resistant statement containing statement_id nullifier and predicate evaluation result".to_string(),
                        },
                    ],
                    description: "Verifies MPT state proof against HeaderRecord and evaluates predicate".to_string(),
                },
            ],
            error_codes: vec![
                SpelErrorCode {
                    code: 0x01,
                    name: "InsufficientParticipation".to_string(),
                    description: "Less than 2/3 sync committee supermajority (requires >= 342 of 512 validators)".to_string(),
                },
                SpelErrorCode {
                    code: 0x02,
                    name: "BlsVerificationFailed".to_string(),
                    description: "Aggregate BLS12-381 signature verification failed at final exponentiation".to_string(),
                },
                SpelErrorCode {
                    code: 0x03,
                    name: "StaleUpdate".to_string(),
                    description: "Submitted update slot is older than or equal to current finalized slot".to_string(),
                },
                SpelErrorCode {
                    code: 0x04,
                    name: "InvalidSyncCommitteeBranch".to_string(),
                    description: "SSZ generalized index 54 or 55 Merkle proof failed validation".to_string(),
                },
                SpelErrorCode {
                    code: 0x05,
                    name: "MissingExecutionPayload".to_string(),
                    description: "Consensus update omitted mandatory execution payload header or generalized index 25 branch".to_string(),
                },
                SpelErrorCode {
                    code: 0x06,
                    name: "MptProofVerificationFailed".to_string(),
                    description: "Merkle-Patricia Trie proof does not resolve to the authenticated state or receipts root".to_string(),
                },
                SpelErrorCode {
                    code: 0x07,
                    name: "PredicateFailed".to_string(),
                    description: "Evaluated predicate condition returned false".to_string(),
                },
                SpelErrorCode {
                    code: 0x08,
                    name: "NullifierAlreadySpent".to_string(),
                    description: "Statement ID has already been claimed (replay prevention)".to_string(),
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spel_canonical_schema_validity() {
        let def = SpelModuleDefinition::canonical();
        assert_eq!(def.module_name, "mosoo_ethereum_attester");
        assert_eq!(def.methods.len(), 5);
        assert_eq!(def.error_codes.len(), 8);

        // Verify method IDs are unique
        let mut ids = std::collections::HashSet::new();
        for m in &def.methods {
            assert!(
                ids.insert(m.method_id),
                "Duplicate method ID: {}",
                m.method_id
            );
            assert!(
                m.gas_limit <= 10_000_000,
                "Method gas limit exceeds LEZ cap"
            );
        }

        // Verify JSON serialization
        let json = serde_json::to_string_pretty(&def).expect("SPEL IDL serializes to JSON");
        assert!(json.contains("mosoo_ethereum_attester"));
        assert!(json.contains("begin_update"));
    }
}
