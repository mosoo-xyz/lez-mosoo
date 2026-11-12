#![allow(deprecated)]

use super::*;

fn min_32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn make_statement(
    chain_id: u64,
    holds: bool,
    id_seed: u8,
    wei: u64,
    attester: [u8; 32],
) -> VerifiedStatement {
    let user_addr = [0x42; 20];
    use sha2::Digest;
    let subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();
    let mut verified_value = [0u8; 32];
    verified_value[24..32].copy_from_slice(&wei.to_be_bytes());
    let mut stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(chain_id),
        source_instance_id: [0u8; 32],
        source_instance_pda: TrustedBridgeConfig::canonical()
            .get_trusted_instance(chain_id)
            .unwrap_or([0u8; 32]),
        attester_program_id: attester,
        statement_id: [0u8; 32],
        predicate_holds: holds,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
        binding: StatementBinding::Account { address: user_addr },
    };
    stmt.statement_id = if id_seed != 0 {
        stmt.derive_canonical_id()
    } else {
        [0u8; 32]
    };
    stmt
}

#[allow(clippy::too_many_arguments)]
fn make_deposit_statement(
    chain_id: u64,
    holds: bool,
    id_seed: u8,
    wei: u64,
    attester: [u8; 32],
    deposit_contract: [u8; 20],
    sender: [u8; 20],
    recipient: [u8; 32],
) -> VerifiedStatement {
    let mut verified_value = [0u8; 32];
    verified_value[24..32].copy_from_slice(&wei.to_be_bytes());
    let block_hash = [0x22; 32];
    let slot = 200u64;
    let tx_index = 1u64;
    let log_index = 0usize;
    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    let mut stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(chain_id),
        source_instance_id: [0u8; 32],
        source_instance_pda: TrustedBridgeConfig::canonical()
            .get_trusted_instance(chain_id)
            .unwrap_or([0u8; 32]),
        attester_program_id: attester,
        statement_id: [0u8; 32],
        predicate_holds: holds,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    };
    stmt.statement_id = if id_seed != 0 {
        stmt.derive_canonical_id()
    } else {
        [0u8; 32]
    };
    stmt
}

#[test]
fn valid_ether_claim_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x10,
        1_000_000_000_000_000_000,
        MOSOO_PROGRAM_ID,
    );
    let result = claim_ether(&statement, &mut nullifiers, 1_000_000_000_000_000_000);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1_000_000_000_000_000_000);
}

#[test]
fn duplicate_ether_claim_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x20, 100, MOSOO_PROGRAM_ID);
    claim_ether(&statement, &mut nullifiers, 100).unwrap();
    let result = claim_ether(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(EtherReceiverError::AlreadyClaimed)));
}

#[test]
fn wrong_chain_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(11_155_111, true, 0x30, 100, MOSOO_PROGRAM_ID);
    let result = claim_ether(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(EtherReceiverError::WrongChain(_))));
}

#[test]
fn test_sepolia_chain_claim_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x30, 100, MOSOO_PROGRAM_ID);
    let account = StatementAccount::new_authentic(statement);
    let result = claim_ether_authenticated_pda_u256(&account, &mut nullifiers, U256::from(100u64));
    assert_eq!(result, Ok(U256::from(100u64)));
}

#[test]
fn failed_predicate_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, false, 0x40, 100, MOSOO_PROGRAM_ID);
    let result = claim_ether(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(EtherReceiverError::PredicateFailed)));
}

#[test]
fn unauthenticated_attester_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let bogus_attester = [0xef; 32];
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x45, 100, bogus_attester);
    let result = claim_ether(&statement, &mut nullifiers, 100);
    assert_eq!(result, Err(EtherReceiverError::UnauthenticatedAttester));
}

#[test]
fn balance_too_low_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x46, 50, MOSOO_PROGRAM_ID);
    let result = claim_ether(&statement, &mut nullifiers, 100);
    assert_eq!(
        result,
        Err(EtherReceiverError::BalanceTooLow {
            actual: 50,
            required: 100
        })
    );
}

#[test]
fn test_native_eth_deposit_with_sender_recipient_and_amount_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x50,
        2_500_000_000_000_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1_000_000_000_000_000_000,
    };
    let credited = claim_native_eth_deposit(&deposit_claim, &mut nullifiers)
        .expect("Valid deposit claim should succeed");
    assert_eq!(credited, 2_500_000_000_000_000_000);
}

#[test]
fn test_native_eth_deposit_wrong_contract_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x51,
        2_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0x99; 20], // wrong deposit contract
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1_000_000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(EtherReceiverError::ContractMismatch {
            expected: [0x99; 20],
            actual: [0xaa; 20],
        })
    );
}

#[test]
fn test_native_eth_deposit_wrong_sender_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x52,
        2_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0x77; 20], // wrong sender
        recipient: [0xcc; 32],
        min_wei: 1_000_000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(EtherReceiverError::SenderMismatch {
            expected: [0x77; 20],
            actual: [0xbb; 20],
        })
    );
}

#[test]
fn test_native_eth_deposit_wrong_recipient_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x53,
        2_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0x33; 32], // wrong recipient
        min_wei: 1_000_000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(EtherReceiverError::RecipientMismatch {
            expected: [0x33; 32],
            actual: [0xcc; 32],
        })
    );
}

#[test]
fn test_native_eth_deposit_wrong_statement_type_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    // Raw account balance statement instead of NativeEthDeposit
    let statement = make_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x54,
        2_000_000,
        MOSOO_PROGRAM_ID,
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1_000_000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(result, Err(EtherReceiverError::InvalidStatementType(0)));
}

#[test]
fn test_native_eth_deposit_subject_key_tamper_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let mut statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x55,
        2_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    // Tamper with subject_key
    statement.subject_key[0] ^= 0xff;
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1_000_000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(result, Err(EtherReceiverError::SubjectKeyMismatch));
}

#[test]
fn test_native_eth_deposit_duplicate_replay_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x56,
        1_000_000_000_000_000_000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1_000_000_000_000_000_000,
    };
    claim_native_eth_deposit(&deposit_claim, &mut nullifiers).unwrap();
    let replay_result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(replay_result, Err(EtherReceiverError::AlreadyClaimed));
}

#[test]
fn test_native_eth_deposit_insufficient_wei_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x57,
        500,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(EtherReceiverError::BalanceTooLow {
            actual: 500,
            required: 1000
        })
    );
}

#[test]
fn test_native_eth_deposit_unauthenticated_attester_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let bogus_attester = [0x99; 32];
    let statement = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x58,
        1000,
        bogus_attester,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(result, Err(EtherReceiverError::UnauthenticatedAttester));
}

#[test]
fn test_native_eth_deposit_wrong_chain_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        999_999, // Unsupported chain ID
        true,
        0x59,
        1000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(result, Err(EtherReceiverError::WrongChain(999_999)));
}

#[test]
fn test_native_eth_deposit_sepolia_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    let statement = make_deposit_statement(
        ETH_SEPOLIA_CHAIN_ID, // Sepolia testnet
        true,
        0x59,
        1000,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        [0xbb; 20],
        [0xcc; 32],
    );
    let deposit_claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: [0xaa; 20],
        sender: [0xbb; 20],
        recipient: [0xcc; 32],
        min_wei: 1000,
    };
    let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
    assert_eq!(result, Ok(1000));
}

#[test]
fn test_claim_ether_atomic_account_balance_succeeds() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    let balance_u64: u64 = 5_000_000_000_000_000_000; // 5 ETH
    let balance = U256::from(balance_u64);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(Address::from(user_addr), balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000_000_000_000_000),
        },
        expected_address: user_addr,
        recipient: [0x33; 32],
        min_wei: 1_000_000_000_000_000_000,
    };

    let credited =
        claim_ether_atomic(args.clone(), &mut nullifiers).expect("Atomic ether claim must succeed");
    assert_eq!(credited, balance_u64);

    // Replay rejection
    let replay = claim_ether_atomic(args, &mut nullifiers);
    assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
}

#[test]
fn test_claim_ether_atomic_u256_large_amount_succeeds() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    // 50 ETH = 50 * 10^18 wei >> u64::MAX (18.44 * 10^18)
    let large_wei = U256::from(50_000_000_000_000_000_000u128);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(user_addr.into(), large_wei);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let mut min_32 = [0u8; 32];
    min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

    let args = AtomicEtherClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: min_32 },
        expected_address: user_addr,
        recipient: [0x33; 32],
        min_wei: U256::from(10_000_000_000_000_000_000u128), // 10 ETH
    };

    let credited = claim_ether_atomic_u256(args.clone(), &mut nullifiers)
        .expect("Atomic U256 ether claim for 50 ETH MUST succeed");
    assert_eq!(credited, large_wei);

    // Replay rejection
    let replay = claim_ether_atomic_u256(args, &mut nullifiers);
    assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
}

#[test]
fn test_claim_account_balance_atomic_typed_receipt() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    let balance_u64 = 7_000_000_000_000_000_000u64;
    let balance = U256::from(balance_u64);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(Address::from(user_addr), balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000_000_000_000_000),
        },
        expected_address: user_addr,
        recipient: [0x33; 32],
        min_wei: 1_000_000_000_000_000_000,
    };

    let attestation = claim_account_balance_atomic(args.clone(), &mut nullifiers)
        .expect("Atomic account balance attestation must succeed");
    assert_eq!(attestation.account_address, user_addr);
    assert_eq!(attestation.verified_balance_wei, balance_u64);
    assert_eq!(attestation.slot, 10_000_000);

    // Replay rejection
    let replay = claim_account_balance_atomic(args, &mut nullifiers);
    assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
}

#[test]
fn test_claim_ether_atomic_rejects_unauthenticated_header() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    let balance = U256::from(5_000_000_000_000_000_000u64);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(Address::from(user_addr), balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    // Forged beacon block root
    let forged_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0xba; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AtomicEtherClaimArgs {
        instance,
        header: forged_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000_000_000_000_000),
        },
        expected_address: user_addr,
        recipient: [0x33; 32],
        min_wei: 1_000_000_000_000_000_000,
    };

    let res = claim_ether_atomic(args, &mut nullifiers);
    assert!(matches!(res, Err(EtherReceiverError::AttestationFailed(_))));
}

#[test]
fn test_claim_ether_atomic_rejects_address_mismatch() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    let balance = U256::from(5_000_000_000_000_000_000u64);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(Address::from(user_addr), balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000_000_000_000_000),
        },
        expected_address: [0x99; 20], // mismatched address
        recipient: [0x33; 32],
        min_wei: 1_000_000_000_000_000_000,
    };

    let res = claim_ether_atomic(args, &mut nullifiers);
    assert!(matches!(
        res,
        Err(EtherReceiverError::ContractMismatch { .. })
    ));
}

#[test]
fn test_meth_ledger_deposit_mint_and_balance() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let recipient = [0x55; 32];
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];
    let wei = 2_000_000_000_000_000_000u64; // 2 ETH

    let stmt = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x10,
        wei,
        MOSOO_PROGRAM_ID,
        deposit_contract,
        sender,
        recipient,
    );

    let claim = NativeEthDepositClaim {
        statement: stmt,
        expected_deposit_contract: deposit_contract,
        sender,
        recipient,
        min_wei: 1_000_000_000_000_000_000,
    };

    let new_balance = ledger.mint_meth(&claim, &mut nullifiers).unwrap();
    assert_eq!(new_balance, 2_000_000_000_000_000_000);
    assert_eq!(ledger.get_balance(&recipient), 2_000_000_000_000_000_000);
    assert_eq!(ledger.total_supply_wei, 2_000_000_000_000_000_000);

    let account = ledger.get_account(&recipient).unwrap();
    assert_eq!(account.deposit_count, 1);
    assert_eq!(account.burn_count, 0);
}

#[test]
fn test_meth_ledger_transfer_between_lez_accounts() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let alice = [0xAA; 32];
    let bob = [0xBB; 32];
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];

    let stmt = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x20,
        5_000_000_000_000_000_000,
        MOSOO_PROGRAM_ID,
        deposit_contract,
        sender,
        alice,
    );

    let claim = NativeEthDepositClaim {
        statement: stmt,
        expected_deposit_contract: deposit_contract,
        sender,
        recipient: alice,
        min_wei: 1_000_000_000_000_000_000,
    };

    ledger.mint_meth(&claim, &mut nullifiers).unwrap();
    assert_eq!(ledger.get_balance(&alice), 5_000_000_000_000_000_000);

    // Alice transfers 2 ETH of mETH to Bob
    ledger
        .transfer_meth(&alice, &bob, 2_000_000_000_000_000_000)
        .unwrap();
    assert_eq!(ledger.get_balance(&alice), 3_000_000_000_000_000_000);
    assert_eq!(ledger.get_balance(&bob), 2_000_000_000_000_000_000);
    assert_eq!(ledger.total_supply_wei, 5_000_000_000_000_000_000);
}

#[test]
fn test_meth_ledger_transfer_insufficient_balance_rejected() {
    let mut ledger = MethLedger::new();
    let alice = [0xAA; 32];
    let bob = [0xBB; 32];

    // Transfer with zero/non-existent account
    let res = ledger.transfer_meth(&alice, &bob, 1_000_000_000);
    assert!(matches!(res, Err(EtherReceiverError::AccountNotFound(_))));
}

#[test]
fn test_meth_ledger_burn_produces_valid_burn_receipt() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let alice = [0xAA; 32];
    let eth_recipient = [0x77; 20];
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];

    let stmt = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x30,
        10_000_000_000_000_000_000, // 10 ETH
        MOSOO_PROGRAM_ID,
        deposit_contract,
        sender,
        alice,
    );

    let claim = NativeEthDepositClaim {
        statement: stmt,
        expected_deposit_contract: deposit_contract,
        sender,
        recipient: alice,
        min_wei: 1_000_000_000_000_000_000,
    };

    ledger.mint_meth(&claim, &mut nullifiers).unwrap();

    // Alice burns 4 ETH of mETH to unlock on Ethereum
    let burn_receipt = ledger
        .burn_meth(
            ETH_MAINNET_CHAIN_ID,
            &alice,
            4_000_000_000_000_000_000,
            &eth_recipient,
            62180,
        )
        .unwrap();

    assert_eq!(burn_receipt.amount_wei, 4_000_000_000_000_000_000);
    assert_eq!(burn_receipt.eth_recipient, eth_recipient);
    assert_eq!(burn_receipt.lez_owner, alice);
    assert_eq!(burn_receipt.burn_nonce, 1);
    assert_eq!(burn_receipt.lez_slot, 62180);

    // Check balances and invariants
    assert_eq!(ledger.get_balance(&alice), 6_000_000_000_000_000_000);
    assert_eq!(ledger.total_supply_wei, 6_000_000_000_000_000_000);
    assert_eq!(ledger.total_burned_wei, 4_000_000_000_000_000_000);

    // Verify receipt retrievability
    let retrieved = ledger.get_burn_receipt(&burn_receipt.burn_id).unwrap();
    assert_eq!(retrieved.burn_id, burn_receipt.burn_id);
}

#[test]
fn test_meth_ledger_burn_insufficient_balance_rejected() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let alice = [0xAA; 32];
    let eth_recipient = [0x77; 20];
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];

    let stmt = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x40,
        1_000_000_000_000_000_000, // 1 ETH
        MOSOO_PROGRAM_ID,
        deposit_contract,
        sender,
        alice,
    );

    let claim = NativeEthDepositClaim {
        statement: stmt,
        expected_deposit_contract: deposit_contract,
        sender,
        recipient: alice,
        min_wei: 1_000_000_000_000_000_000,
    };

    ledger.mint_meth(&claim, &mut nullifiers).unwrap();

    // Alice tries to burn 2 ETH when she only has 1 ETH
    let res = ledger.burn_meth(
        ETH_MAINNET_CHAIN_ID,
        &alice,
        2_000_000_000_000_000_000,
        &eth_recipient,
        62180,
    );
    assert!(matches!(
        res,
        Err(EtherReceiverError::InsufficientBalance { .. })
    ));
}

#[test]
fn test_meth_ledger_double_deposit_mint_rejected_by_nullifier() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let alice = [0xAA; 32];
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];

    let stmt = make_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x50,
        3_000_000_000_000_000_000,
        MOSOO_PROGRAM_ID,
        deposit_contract,
        sender,
        alice,
    );

    let claim = NativeEthDepositClaim {
        statement: stmt.clone(),
        expected_deposit_contract: deposit_contract,
        sender,
        recipient: alice,
        min_wei: 1_000_000_000_000_000_000,
    };

    // First mint succeeds
    ledger.mint_meth(&claim, &mut nullifiers).unwrap();

    // Second mint attempt with the same claim fails due to nullifier
    let err = ledger.mint_meth(&claim, &mut nullifiers).unwrap_err();
    assert_eq!(err, EtherReceiverError::AlreadyClaimed);
    assert_eq!(ledger.get_balance(&alice), 3_000_000_000_000_000_000);
}

#[test]
fn test_claim_ether_rejects_statement_id_tampering() {
    let mut nullifiers = EtherNullifierSet::new();
    let mut stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x10, 100, MOSOO_PROGRAM_ID);
    // Attacker mutates statement_id to bypass nullifier tracking
    stmt.statement_id = [0xfe; 32];
    let res = claim_ether(&stmt, &mut nullifiers, 100);
    assert_eq!(res.unwrap_err(), EtherReceiverError::StatementIdMismatch);
}

#[test]
fn test_ether_nullifier_pda_derivation_and_restart_persistence() {
    let mut nullifiers = EtherNullifierSet::new();
    let stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x30, 500, MOSOO_PROGRAM_ID);

    let pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &stmt.statement_id);
    assert_ne!(pda, [0u8; 32]);

    // First claim succeeds on runtime instance 1
    claim_ether(&stmt, &mut nullifiers, 100).expect("claim succeeds");

    // Export PDA records (simulating LEZ account storage persistence)
    let records = nullifiers.export_pda_records(10_000_000);
    assert!(!records.is_empty());

    // Simulate runtime restart with fresh memory state
    let mut restarted = EtherNullifierSet::new();
    assert!(!restarted.is_used(&stmt.statement_id));

    // Restore state from persistent LEZ PDA accounts
    restarted.restore_pda_records(&records);
    assert!(restarted.is_used(&stmt.statement_id));

    // Replay attempt across restart cycle MUST BE REJECTED!
    let replay_res = claim_ether(&stmt, &mut restarted, 100);
    assert_eq!(replay_res.unwrap_err(), EtherReceiverError::AlreadyClaimed);
}

#[test]
fn test_meth_ledger_mint_atomic_rejects_unbacked_account_balance() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();
    let user_addr = [0x42; 20];
    let balance = U256::from(5_000_000_000_000_000_000u64);

    let (state_root, proof_nodes, account_rlp) =
        build_test_account_balance_proof(Address::from(user_addr), balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x88; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x88; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: Address::from(user_addr),
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000_000_000_000_000),
        },
        expected_address: user_addr,
        recipient: [0x33; 32],
        min_wei: 1_000_000_000_000_000_000,
    };

    // Attempting to mint bridge mETH from an ordinary Ethereum account balance MUST FAIL!
    let res = ledger.mint_meth_atomic(args, &mut nullifiers);
    assert_eq!(res.unwrap_err(), EtherReceiverError::DepositBackingRequired);
}

#[test]
fn test_meth_ledger_mint_atomic_rejects_zero_address_and_untrusted_locker() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_eth_canonical_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let authentic_locker = [0xaa; 20]; // Registered test locker
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
    let fake_locker = [0x77; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let amount_wei = U256::from(5_000_000_000_000_000_000u64); // 5 ETH
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
        Address::from(authentic_locker),
        Address::from(sender),
        recipient,
        amount_wei,
        nonce,
    );

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: [0x88; 32],
        current_receipts_root: receipts_root.0,
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: [0x88; 32],
        receipts_root: receipts_root.0,
    };

    let proof = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(authentic_locker),
            sender: Address::from(sender),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    // 1. Zero address expected_address strictly rejected (no bypass)
    let zero_args = AtomicEtherClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_address: [0u8; 20],
        recipient,
        min_wei: 1_000_000,
    };
    let err_zero = ledger.mint_meth_atomic(zero_args, &mut nullifiers);
    assert_eq!(err_zero, Err(EtherReceiverError::DepositBackingRequired));

    // 2. Caller-supplied fake expected locker rejected against program-owned configuration
    let fake_args = AtomicEtherClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_address: fake_locker,
        recipient,
        min_wei: 1_000_000,
    };
    let err_fake = ledger.mint_meth_atomic(fake_args, &mut nullifiers);
    assert_eq!(
        err_fake,
        Err(EtherReceiverError::ContractMismatch {
            expected: authentic_locker,
            actual: fake_locker,
        })
    );
}

#[test]
fn test_claim_native_eth_deposit_atomic_rejects_untrusted_vault_and_zero_address() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_eth_canonical_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = EtherNullifierSet::new();
    let canonical_sepolia = mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_LOCKER;
    let fake_vault = [0x55; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let amount_wei = U256::from(2_000_000_000_000_000_000u64);
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
        Address::from(canonical_sepolia),
        Address::from(sender),
        recipient,
        amount_wei,
        nonce,
    );

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x77; 32],
        current_execution_state_root: [0x88; 32],
        current_receipts_root: receipts_root.0,
    };

    let header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: [0x88; 32],
        receipts_root: receipts_root.0,
    };

    let proof = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(canonical_sepolia),
            sender: Address::from(sender),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    // 1. Zero address rejected
    let zero_args = AtomicEtherClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_address: [0u8; 20],
        recipient,
        min_wei: 1_000_000,
    };
    let err_zero = claim_native_eth_deposit_atomic(zero_args, &mut nullifiers);
    assert_eq!(err_zero, Err(EtherReceiverError::DepositBackingRequired));

    // 2. Fake vault rejected against canonical locker
    let fake_args = AtomicEtherClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_address: fake_vault,
        recipient,
        min_wei: 1_000_000,
    };
    let err_fake = claim_native_eth_deposit_atomic(fake_args, &mut nullifiers);
    assert_eq!(
        err_fake,
        Err(EtherReceiverError::ContractMismatch {
            expected: canonical_sepolia,
            actual: fake_vault,
        })
    );

    // 3. Authentic canonical vault succeeds
    let valid_args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_address: canonical_sepolia,
        recipient,
        min_wei: 1_000_000,
    };
    let receipt = claim_native_eth_deposit_atomic(valid_args, &mut nullifiers)
        .expect("Authentic canonical Sepolia deposit claim must succeed");
    assert_eq!(receipt.deposit_contract, canonical_sepolia);
    assert_eq!(receipt.amount_wei, amount_wei);
}

#[test]
fn test_derive_burn_id_deterministic() {
    let id1 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
    let id2 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
    assert_eq!(id1, id2);

    let id3 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_001, 1, 100);
    assert_ne!(id1, id3);
}

#[test]
fn test_claim_ether_u256_amounts_exceeding_u64_max_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    // 50 ETH = 50 * 10^18 wei = 50_000_000_000_000_000_000 > u64::MAX (~18.44 ETH in wei)
    let large_wei: u128 = 50_000_000_000_000_000_000;
    assert!(large_wei > u64::MAX as u128);

    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let block_hash = [0x44; 32];
    let slot = 10_500_000;
    let tx_index = 1;
    let log_index = 0;

    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    let mut verified_value = [0u8; 32];
    verified_value.copy_from_slice(&U256::from(large_wei).to_be_bytes::<32>());

    let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
        ETH_MAINNET_CHAIN_ID,
        &subject_key,
        PROOF_TYPE_ETH_DEPOSIT,
        &verified_value,
    );

    let mut statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(ETH_MAINNET_CHAIN_ID),
        source_instance_id: [0u8; 32],
        source_instance_pda: mosoo_core::types::CANONICAL_MAINNET_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: true,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    };
    statement.statement_id = statement.derive_canonical_id();

    // Standard u64 claim fails closed with overflow protection
    let u64_res = claim_ether(&statement, &mut nullifiers, 1_000_000_000);
    assert!(matches!(
        u64_res,
        Err(EtherReceiverError::AttestationFailed(_))
    ));

    // U256 claim succeeds
    let claimed = claim_ether_u256(&statement, &mut nullifiers, U256::from(large_wei))
        .expect("claim_ether_u256 for > u64::MAX wei must succeed");
    assert_eq!(claimed, U256::from(large_wei));

    // Replay rejected
    let replay = claim_ether_u256(&statement, &mut nullifiers, U256::from(large_wei));
    assert_eq!(replay.unwrap_err(), EtherReceiverError::AlreadyClaimed);
}

#[test]
fn test_claim_ether_u128_amounts_exceeding_u64_max_succeeds() {
    let mut nullifiers = EtherNullifierSet::new();
    let large_wei: u128 = 25_000_000_000_000_000_000; // 25 ETH
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let block_hash = [0x44; 32];
    let slot = 10_500_000;
    let tx_index = 1;
    let log_index = 0;

    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    let mut verified_value = [0u8; 32];
    verified_value.copy_from_slice(&U256::from(large_wei).to_be_bytes::<32>());

    let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
        ETH_MAINNET_CHAIN_ID,
        &subject_key,
        PROOF_TYPE_ETH_DEPOSIT,
        &verified_value,
    );

    let mut statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(ETH_MAINNET_CHAIN_ID),
        source_instance_id: [0u8; 32],
        source_instance_pda: mosoo_core::types::CANONICAL_MAINNET_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: true,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    };
    statement.statement_id = statement.derive_canonical_id();

    #[allow(deprecated)]
    let claimed = claim_ether_u128(&statement, &mut nullifiers, large_wei)
        .expect("claim_ether_u128 for > u64::MAX wei must succeed");
    assert_eq!(claimed, large_wei);
}

#[test]
fn test_claim_ether_authenticated_pda_u256_provenance_verification() {
    let mut nullifiers = EtherNullifierSet::new();
    let deposit_contract = [0x11; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let block_hash = [0x44; 32];
    let slot = 10_500_000;
    let tx_index = 1;
    let log_index = 0;
    let wei = U256::from(50_000_000_000_000_000_000u128); // 50 ETH

    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    let mut val_bytes = [0u8; 32];
    val_bytes.copy_from_slice(&wei.to_be_bytes::<32>());

    let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
        ETH_SEPOLIA_CHAIN_ID,
        &subject_key,
        PROOF_TYPE_ETH_DEPOSIT,
        &val_bytes,
    );

    let mut statement = VerifiedStatement {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(ETH_SEPOLIA_CHAIN_ID),
        source_instance_id: [0u8; 32],
        source_instance_pda: mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: true,
        verified_value: val_bytes,
        subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    };
    statement.statement_id = statement.derive_canonical_id();

    // 1. Adversary fabricates statement account with fake owner program ID
    let fake_owner = [0x99; 32];
    let fabricated_account = StatementAccount {
        owner: fake_owner,
        pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
        statement: statement.clone(),
    };
    let err = claim_ether_authenticated_pda_u256(
        &fabricated_account,
        &mut nullifiers,
        U256::from(100u64),
    )
    .expect_err("Fabricated account with fake owner must be rejected");
    assert_eq!(err, EtherReceiverError::UnauthenticatedAttester);

    // 2. Adversary fabricates statement account with mismatched PDA address
    let fake_pda = [0x88; 32];
    let tampered_pda_account = StatementAccount {
        owner: MOSOO_PROGRAM_ID,
        pda_address: fake_pda,
        statement: statement.clone(),
    };
    let err2 = claim_ether_authenticated_pda_u256(
        &tampered_pda_account,
        &mut nullifiers,
        U256::from(100u64),
    )
    .expect_err("Account with tampered PDA address must be rejected");
    assert_eq!(err2, EtherReceiverError::UnauthenticatedAttester);

    // 3. Authentic statement account succeeds
    let authentic_account = StatementAccount::new_authentic(statement);
    let claimed =
        claim_ether_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
            .expect("Authentic statement account must be accepted");
    assert_eq!(claimed, wei);

    // 4. Replay rejected
    let replay =
        claim_ether_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
            .expect_err("Replay claim on statement account must be rejected");
    assert_eq!(replay, EtherReceiverError::AlreadyClaimed);
}

#[test]
fn test_meth_ledger_authenticated_pda_mint_succeeds_and_fabricated_rejected() {
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();
    let deposit_contract = [0x11; 20];
    ledger.register_trusted_locker(ETH_SEPOLIA_CHAIN_ID, deposit_contract);

    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let block_hash = [0x44; 32];
    let slot = 10_500_000;
    let tx_index = 1;
    let log_index = 0;
    let amount_wei = U256::from(50_000_000_000_000_000_000u128); // 50 ETH

    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
        ETH_SEPOLIA_CHAIN_ID,
        &subject_key,
        PROOF_TYPE_ETH_DEPOSIT,
        &amount_wei.to_be_bytes::<32>(),
    );

    let mut statement = VerifiedStatement {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(ETH_SEPOLIA_CHAIN_ID),
        source_instance_id: [0u8; 32],
        source_instance_pda: mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: true,
        verified_value: amount_wei.to_be_bytes::<32>(),
        subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    };
    statement.statement_id = statement.derive_canonical_id();

    // 1. Fabricated account rejected
    let fabricated = StatementAccount {
        owner: [0xfe; 32],
        pda_address: [0xdd; 32],
        statement: statement.clone(),
    };
    let err =
        ledger.mint_deposit_authenticated_pda_u256(&fabricated, deposit_contract, &mut nullifiers);
    assert_eq!(err, Err(EtherReceiverError::UnauthenticatedAttester));

    // 2. Zero address bypass strictly rejected
    let authentic = StatementAccount::new_authentic(statement);
    let zero_err =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, [0u8; 20], &mut nullifiers);
    assert_eq!(zero_err, Err(EtherReceiverError::DepositBackingRequired));

    // 3. Mismatched deposit vault rejected
    let mismatch =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xee; 20], &mut nullifiers);
    assert_eq!(
        mismatch,
        Err(EtherReceiverError::ContractMismatch {
            expected: deposit_contract,
            actual: [0xee; 20],
        })
    );

    // 3. Authentic account mints 50 ETH successfully
    let minted = ledger
        .mint_deposit_authenticated_pda_u256(&authentic, deposit_contract, &mut nullifiers)
        .expect("Authentic PDA mint must succeed");
    assert_eq!(minted, amount_wei);
    assert_eq!(ledger.get_balance(&recipient), amount_wei.to::<u128>());
    assert_eq!(ledger.total_supply_wei, amount_wei.to::<u128>());

    // 4. Double-mint replay rejected by nullifier
    let replay =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, deposit_contract, &mut nullifiers);
    assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
}
