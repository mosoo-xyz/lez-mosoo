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
    amount: u64,
    attester: [u8; 32],
) -> VerifiedStatement {
    make_erc20_statement(
        chain_id, holds, id_seed, amount, attester, [0xaa; 20], [0x11; 20], [0x22; 32],
    )
}

#[allow(clippy::too_many_arguments)]
fn make_erc20_statement(
    chain_id: u64,
    holds: bool,
    id_seed: u8,
    amount: u64,
    attester: [u8; 32],
    token_contract: [u8; 20],
    sender: [u8; 20],
    recipient: [u8; 32],
) -> VerifiedStatement {
    let mut verified_value = [0u8; 32];
    verified_value[24..32].copy_from_slice(&amount.to_be_bytes());
    let block_hash = [0x11; 32];
    let slot = 100u64;
    let tx_index = 0u64;
    let log_index = 0usize;
    let subject_key = derive_erc20_transfer_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &token_contract,
        &sender,
        &recipient,
    );
    let mut stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(chain_id),
        source_instance_id: [0u8; 32],
        source_instance_pda: match chain_id {
            ETH_SEPOLIA_CHAIN_ID => mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
            ETH_MAINNET_CHAIN_ID => mosoo_core::types::CANONICAL_MAINNET_MOSOO_INSTANCE,
            ETH_HOLESKY_CHAIN_ID => mosoo_core::types::CANONICAL_HOLESKY_MOSOO_INSTANCE,
            _ => [0u8; 32],
        },
        attester_program_id: attester,
        statement_id: [0u8; 32],
        predicate_holds: holds,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
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
fn valid_claim_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x01, 100, MOSOO_PROGRAM_ID);
    let result = claim(&statement, &mut nullifiers, 100);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 100);
}

#[test]
fn duplicate_claim_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x02, 100, MOSOO_PROGRAM_ID);
    claim(&statement, &mut nullifiers, 100).unwrap();
    let result = claim(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(ReceiverError::AlreadyClaimed)));
}

#[test]
fn wrong_chain_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x03, 100, MOSOO_PROGRAM_ID);
    let result = claim(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(ReceiverError::WrongChain(_))));
}

#[test]
fn test_sepolia_chain_claim_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x03, 100, MOSOO_PROGRAM_ID);
    let account = StatementAccount::new_authentic(statement);
    let result = claim_authenticated_pda_u256(&account, &mut nullifiers, U256::from(100u64));
    assert_eq!(result, Ok(U256::from(100u64)));
}

#[test]
fn failed_predicate_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, false, 0x04, 100, MOSOO_PROGRAM_ID);
    let result = claim(&statement, &mut nullifiers, 100);
    assert!(matches!(result, Err(ReceiverError::PredicateFailed)));
}

#[test]
fn unauthenticated_attester_rejected() {
    let mut nullifiers = NullifierSet::new();
    let bogus_attester = [0xde; 32];
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x05, 100, bogus_attester);
    let result = claim(&statement, &mut nullifiers, 100);
    assert_eq!(result, Err(ReceiverError::UnauthenticatedAttester));
}

#[test]
fn claim_amount_too_low_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x06, 50, MOSOO_PROGRAM_ID);
    let result = claim(&statement, &mut nullifiers, 100);
    assert_eq!(
        result,
        Err(ReceiverError::AmountTooLow {
            min_amount: 100,
            actual: 50
        })
    );
}

#[test]
fn test_erc20_transfer_claim_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x07,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let minted = claim_erc20_transfer(&claim, &mut nullifiers)
        .expect("Valid ERC20 transfer claim should succeed");
    assert_eq!(minted, 500_000);
}

#[test]
fn test_erc20_transfer_wrong_token_contract_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x08,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x99; 20], // wrong token contract
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(ReceiverError::TokenContractMismatch {
            expected: [0x99; 20],
            actual: [0x11; 20],
        })
    );
}

#[test]
fn test_erc20_transfer_wrong_sender_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x09,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x88; 20], // wrong sender
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(ReceiverError::SenderMismatch {
            expected: [0x88; 20],
            actual: [0x22; 20],
        })
    );
}

#[test]
fn test_erc20_transfer_wrong_recipient_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x0a,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x77; 32], // wrong recipient
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(ReceiverError::RecipientMismatch {
            expected: [0x77; 32],
            actual: [0x33; 32],
        })
    );
}

#[test]
fn test_erc20_transfer_wrong_statement_type_rejected() {
    let mut nullifiers = NullifierSet::new();
    // Raw account balance statement instead of Erc20Transfer
    let mut statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x0b, 500_000, MOSOO_PROGRAM_ID);
    statement.proof_type_tag = 0;
    statement.binding = StatementBinding::Account {
        address: [0x11; 20],
    };
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(result, Err(ReceiverError::InvalidStatementType(0)));
}

#[test]
fn test_erc20_transfer_subject_key_tamper_rejected() {
    let mut nullifiers = NullifierSet::new();
    let mut statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x0c,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    // Tamper with subject_key
    statement.subject_key[0] ^= 0xff;
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(result, Err(ReceiverError::SubjectKeyMismatch));
}

#[test]
fn test_erc20_transfer_insufficient_amount_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x0d,
        50,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(
        result,
        Err(ReceiverError::AmountTooLow {
            min_amount: 100,
            actual: 50
        })
    );
}

#[test]
fn test_erc20_transfer_duplicate_replay_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x0e,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    claim_erc20_transfer(&claim, &mut nullifiers).unwrap();
    let replay_result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(replay_result, Err(ReceiverError::AlreadyClaimed));
}

#[test]
fn test_erc20_transfer_unauthenticated_attester_rejected() {
    let mut nullifiers = NullifierSet::new();
    let bogus_attester = [0x55; 32];
    let statement = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x0f,
        500_000,
        bogus_attester,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(result, Err(ReceiverError::UnauthenticatedAttester));
}

#[test]
fn test_erc20_transfer_wrong_chain_rejected() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        999_999, // Unsupported chain ID
        true,
        0x10,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(result, Err(ReceiverError::WrongChain(999_999)));
}

#[test]
fn test_erc20_transfer_sepolia_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let statement = make_erc20_statement(
        ETH_SEPOLIA_CHAIN_ID, // Sepolia testnet
        true,
        0x10,
        500_000,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 32],
    );
    let claim = Erc20TransferClaim {
        statement,
        token_contract: [0x11; 20],
        sender: [0x22; 20],
        recipient: [0x33; 32],
        min_amount: 100_000,
    };
    let result = claim_erc20_transfer(&claim, &mut nullifiers);
    assert_eq!(result, Ok(500_000));
}

#[test]
fn test_claim_atomic_receipt_log_succeeds() {
    use alloy_primitives::{keccak256, Address, U256};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = NullifierSet::new();
    let emitter_addr = [0xaa; 20];
    let from_addr = [0x11; 20];
    let to_addr = [0x22; 20];
    let amount_u64: u64 = 42_000_000;
    let amount = U256::from(amount_u64);

    let receipt_rlp = build_test_eip1559_transfer_receipt(
        Address::from(emitter_addr),
        Address::from(from_addr),
        Address::from(to_addr),
        amount,
    );
    let tx_index: u64 = 0;
    let key_bytes = alloy_rlp::encode(tx_index);
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
        target: ProofTarget::ReceiptLog {
            tx_index,
            log_index: 0,
            emitter: Address::from(emitter_addr),
            topic0: keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000),
        },
        expected_token_contract: emitter_addr,
        expected_sender: None,
        recipient: [0x33; 32],
        min_amount: 1_000_000,
    };

    let minted =
        claim_atomic(args.clone(), &mut nullifiers).expect("Atomic receipt log claim must succeed");
    assert_eq!(minted, amount_u64);

    // Replay rejection in the same state
    let replay = claim_atomic(args, &mut nullifiers);
    assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
}

#[test]
fn test_claim_atomic_u256_large_amount_succeeds() {
    use alloy_primitives::{keccak256, Address, U256};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = NullifierSet::new();
    let emitter_addr = [0xaa; 20];
    let from_addr = [0x11; 20];
    let to_addr = [0x22; 20];
    // 500,000 tokens (18 dec) >> u64::MAX
    let amount = U256::from(500_000_000_000_000_000_000_000u128);

    let receipt_rlp = build_test_eip1559_transfer_receipt(
        Address::from(emitter_addr),
        Address::from(from_addr),
        Address::from(to_addr),
        amount,
    );
    let tx_index: u64 = 0;
    let key_bytes = alloy_rlp::encode(tx_index);
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
        target: ProofTarget::ReceiptLog {
            tx_index,
            log_index: 0,
            emitter: Address::from(emitter_addr),
            topic0: keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let mut min_32 = [0u8; 32];
    min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: min_32 },
        expected_deposit_contract: [0u8; 20],
        expected_token_contract: emitter_addr,
        expected_sender: None,
        recipient: [0x33; 32],
        min_amount: U256::from(100_000_000_000_000_000_000u128),
    };

    let minted = claim_atomic_u256(args.clone(), &mut nullifiers)
        .expect("Atomic U256 claim for 500,000 tokens MUST succeed");
    assert_eq!(minted, amount);

    // Replay rejection
    let replay = claim_atomic_u256(args, &mut nullifiers);
    assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
}

#[test]
fn test_claim_atomic_rejects_unauthenticated_header() {
    use alloy_primitives::{keccak256, Address, U256};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = NullifierSet::new();
    let emitter_addr = [0xaa; 20];
    let amount = U256::from(42_000_000u64);
    let receipt_rlp = build_test_eip1559_transfer_receipt(
        Address::from(emitter_addr),
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        amount,
    );
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&alloy_rlp::encode(0u64), &receipt_rlp);

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

    // Forged beacon block root
    let forged_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0xba; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: [0x88; 32],
        receipts_root: receipts_root.0,
    };

    let proof = StateProof {
        target: ProofTarget::ReceiptLog {
            tx_index: 0,
            log_index: 0,
            emitter: Address::from(emitter_addr),
            topic0: keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgs {
        instance,
        header: forged_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000),
        },
        expected_token_contract: emitter_addr,
        expected_sender: None,
        recipient: [0x33; 32],
        min_amount: 1_000_000,
    };

    let res = claim_atomic(args, &mut nullifiers);
    assert!(matches!(res, Err(ReceiverError::AttestationFailed(_))));
}

#[test]
fn test_claim_atomic_rejects_contract_mismatch() {
    use alloy_primitives::{keccak256, Address, U256};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut nullifiers = NullifierSet::new();
    let emitter_addr = [0xaa; 20];
    let amount = U256::from(42_000_000u64);
    let receipt_rlp = build_test_eip1559_transfer_receipt(
        Address::from(emitter_addr),
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        amount,
    );
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&alloy_rlp::encode(0u64), &receipt_rlp);

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
        target: ProofTarget::ReceiptLog {
            tx_index: 0,
            log_index: 0,
            emitter: Address::from(emitter_addr),
            topic0: keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast {
            min: min_32(1_000_000),
        },
        expected_token_contract: [0xbb; 20], // mismatched contract
        expected_sender: None,
        recipient: [0x33; 32],
        min_amount: 1_000_000,
    };

    let res = claim_atomic(args, &mut nullifiers);
    assert!(matches!(
        res,
        Err(ReceiverError::TokenContractMismatch { .. })
    ));
}

#[test]
fn test_erc20_ledger_mint_and_balance() {
    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let token = [0x55; 20];
    let recipient = [0xAA; 32];
    let sender = [0x11; 20];
    let amount = 500_000_000u64; // 500 USDC

    let stmt = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x10,
        amount,
        MOSOO_PROGRAM_ID,
        token,
        sender,
        recipient,
    );

    let claim = Erc20TransferClaim {
        statement: stmt,
        token_contract: token,
        sender,
        recipient,
        min_amount: 100_000_000,
    };

    let new_bal = ledger.mint_tokens(&claim, &mut nullifiers).unwrap();
    assert_eq!(new_bal, 500_000_000);
    assert_eq!(ledger.get_balance(&token, &recipient), 500_000_000);
    assert_eq!(ledger.get_total_supply(&token), 500_000_000);
}

#[test]
fn test_erc20_ledger_transfer_between_accounts() {
    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let token = [0x55; 20];
    let alice = [0xAA; 32];
    let bob = [0xBB; 32];
    let sender = [0x11; 20];

    let stmt = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x20,
        1_000_000_000,
        MOSOO_PROGRAM_ID,
        token,
        sender,
        alice,
    );

    let claim = Erc20TransferClaim {
        statement: stmt,
        token_contract: token,
        sender,
        recipient: alice,
        min_amount: 1_000_000,
    };

    ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

    // Alice transfers 400 tokens to Bob
    ledger
        .transfer_tokens(&token, &alice, &bob, 400_000_000)
        .unwrap();
    assert_eq!(ledger.get_balance(&token, &alice), 600_000_000);
    assert_eq!(ledger.get_balance(&token, &bob), 400_000_000);
    assert_eq!(ledger.get_total_supply(&token), 1_000_000_000);
}

#[test]
fn test_erc20_ledger_transfer_insufficient_balance_rejected() {
    let mut ledger = Erc20Ledger::new();
    let token = [0x55; 20];
    let alice = [0xAA; 32];
    let bob = [0xBB; 32];

    let res = ledger.transfer_tokens(&token, &alice, &bob, 100);
    assert!(matches!(res, Err(ReceiverError::AccountNotFound { .. })));
}

#[test]
fn test_erc20_ledger_burn_generates_burn_receipt() {
    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let token = [0x55; 20];
    let alice = [0xAA; 32];
    let eth_recipient = [0x99; 20];
    let sender = [0x11; 20];

    let stmt = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x30,
        800_000_000,
        MOSOO_PROGRAM_ID,
        token,
        sender,
        alice,
    );

    let claim = Erc20TransferClaim {
        statement: stmt,
        token_contract: token,
        sender,
        recipient: alice,
        min_amount: 1_000_000,
    };

    ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

    // Alice burns 300 tokens
    let receipt = ledger
        .burn_tokens(
            ETH_MAINNET_CHAIN_ID,
            &token,
            &alice,
            300_000_000,
            &eth_recipient,
            62_200,
        )
        .unwrap();

    assert_eq!(receipt.amount, 300_000_000);
    assert_eq!(receipt.token, token);
    assert_eq!(receipt.eth_recipient, eth_recipient);
    assert_eq!(receipt.lez_owner, alice);
    assert_eq!(receipt.burn_nonce, 1);
    assert_eq!(receipt.lez_slot, 62_200);

    assert_eq!(ledger.get_balance(&token, &alice), 500_000_000);
    assert_eq!(ledger.get_total_supply(&token), 500_000_000);
    assert_eq!(ledger.get_total_burned(&token), 300_000_000);

    let retrieved = ledger.get_burn_receipt(&receipt.burn_id).unwrap();
    assert_eq!(retrieved.burn_id, receipt.burn_id);
}

#[test]
fn test_erc20_ledger_double_deposit_mint_rejected_by_nullifier() {
    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let token = [0x55; 20];
    let alice = [0xAA; 32];
    let sender = [0x11; 20];

    let stmt = make_erc20_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        0x40,
        200_000_000,
        MOSOO_PROGRAM_ID,
        token,
        sender,
        alice,
    );

    let claim = Erc20TransferClaim {
        statement: stmt,
        token_contract: token,
        sender,
        recipient: alice,
        min_amount: 1_000_000,
    };

    // First mint succeeds
    ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

    // Second mint fails
    let res = ledger.mint_tokens(&claim, &mut nullifiers);
    assert_eq!(res.unwrap_err(), ReceiverError::AlreadyClaimed);
    assert_eq!(ledger.get_balance(&token, &alice), 200_000_000);
}

#[test]
fn test_derive_burn_erc20_id_deterministic() {
    let id1 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_000, 1, 100);
    let id2 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_000, 1, 100);
    assert_eq!(id1, id2);

    let id3 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_001, 1, 100);
    assert_ne!(id1, id3);
}

#[test]
fn test_erc20_claim_rejects_statement_id_tampering() {
    let mut nullifiers = NullifierSet::new();
    let mut stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x10, 100, MOSOO_PROGRAM_ID);
    // Attacker mutates statement_id to bypass nullifier
    stmt.statement_id = [0xfe; 32];
    let res = claim(&stmt, &mut nullifiers, 100);
    assert_eq!(res.unwrap_err(), ReceiverError::StatementIdMismatch);
}

#[test]
fn test_erc20_nullifier_pda_derivation_and_restart_persistence() {
    let mut nullifiers = NullifierSet::new();
    let stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x25, 500, MOSOO_PROGRAM_ID);

    let pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &stmt.statement_id);
    assert_ne!(pda, [0u8; 32]);

    // Process claim on original runtime instance
    claim(&stmt, &mut nullifiers, 100).expect("claim on instance 1 succeeds");

    // Export PDA records (simulating LEZ account storage checkpoint)
    let pda_records = nullifiers.export_pda_records(10_000_000);
    assert!(!pda_records.is_empty());

    // Simulate runtime restart with fresh in-memory process
    let mut restarted_nullifiers = NullifierSet::new();
    assert!(!restarted_nullifiers.is_used(&stmt.statement_id));

    // Restore state from persistent LEZ PDA accounts
    restarted_nullifiers.restore_pda_records(&pda_records);
    assert!(restarted_nullifiers.is_used(&stmt.statement_id));

    // Attempt replay after restart: MUST BE REJECTED!
    let replay_res = claim(&stmt, &mut restarted_nullifiers, 100);
    assert_eq!(replay_res.unwrap_err(), ReceiverError::AlreadyClaimed);
}

#[allow(clippy::too_many_arguments)]
fn make_erc20_deposit_statement(
    chain_id: u64,
    holds: bool,
    amount_u128: u128,
    attester: [u8; 32],
    deposit_contract: [u8; 20],
    token_contract: [u8; 20],
    sender: [u8; 20],
    recipient: [u8; 32],
) -> VerifiedStatement {
    let mut verified_value = [0u8; 32];
    verified_value.copy_from_slice(&U256::from(amount_u128).to_be_bytes::<32>());
    let block_hash = [0x55; 32];
    let slot = 10_500_000;
    let tx_index = 2;
    let log_index = 1;

    let subject_key = derive_erc20_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &token_contract,
        &sender,
        &recipient,
    );
    let mut stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: mosoo_core::crypto::genesis_validators_root(chain_id),
        source_instance_id: [0u8; 32],
        source_instance_pda: match chain_id {
            ETH_SEPOLIA_CHAIN_ID => mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
            ETH_MAINNET_CHAIN_ID => mosoo_core::types::CANONICAL_MAINNET_MOSOO_INSTANCE,
            ETH_HOLESKY_CHAIN_ID => mosoo_core::types::CANONICAL_HOLESKY_MOSOO_INSTANCE,
            _ => [0u8; 32],
        },
        attester_program_id: attester,
        statement_id: [0u8; 32],
        predicate_holds: holds,
        verified_value,
        subject_key,
        proof_type_tag: PROOF_TYPE_ERC20_DEPOSIT,
        binding: StatementBinding::Erc20Deposit {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        },
    };
    stmt.statement_id = stmt.derive_canonical_id();
    stmt
}

#[test]
fn test_claim_u256_amounts_exceeding_u64_max_succeeds() {
    let mut nullifiers = NullifierSet::new();
    // 100 tokens with 18 decimals = 100 * 10^18 = 10^20, which is > u64::MAX (~1.84 * 10^19)
    let large_amount: u128 = 100_000_000_000_000_000_000;
    assert!(large_amount > u64::MAX as u128);

    let statement = make_erc20_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        large_amount,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 20],
        [0x44; 32],
    );

    // Standard u64 claim fails closed with overflow protection error
    let u64_res = claim(&statement, &mut nullifiers, 100);
    assert!(matches!(u64_res, Err(ReceiverError::AttestationFailed(_))));

    // U256 claim succeeds with full 256-bit fidelity
    let claimed_u256 = claim_u256(&statement, &mut nullifiers, U256::from(large_amount))
        .expect("U256 claim for amounts > u64::MAX MUST succeed");
    assert_eq!(claimed_u256, U256::from(large_amount));

    // Duplicate claim rejected
    let replay = claim_u256(&statement, &mut nullifiers, U256::from(large_amount));
    assert_eq!(replay.unwrap_err(), ReceiverError::AlreadyClaimed);
}

#[test]
fn test_claim_u128_amounts_exceeding_u64_max_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let large_amount: u128 = 50_000_000_000_000_000_000; // 50 tokens (18 decimals)
    let statement = make_erc20_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        large_amount,
        MOSOO_PROGRAM_ID,
        [0x11; 20],
        [0x22; 20],
        [0x33; 20],
        [0x44; 32],
    );

    let claimed = claim_u128(&statement, &mut nullifiers, large_amount)
        .expect("u128 claim for amounts > u64::MAX MUST succeed");
    assert_eq!(claimed, large_amount);
}

#[test]
fn test_canonical_deposit_erc20_claim_and_mint_succeeds() {
    let mut nullifiers = NullifierSet::new();
    let mut ledger = Erc20Ledger::new();
    let token = [0x22; 20];
    let deposit_contract = [0x11; 20];
    let sender = [0x33; 20];
    let recipient = [0x44; 32];
    let amount: u128 = 250_000_000_000_000_000_000; // 250 tokens
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, deposit_contract);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token);

    let statement = make_erc20_deposit_statement(
        ETH_MAINNET_CHAIN_ID,
        true,
        amount,
        MOSOO_PROGRAM_ID,
        deposit_contract,
        token,
        sender,
        recipient,
    );

    let claim = Erc20DepositClaim {
        statement,
        deposit_contract,
        token_contract: token,
        sender,
        recipient,
        min_amount: 100_000_000_000_000_000_000,
    };

    let new_bal = ledger
        .mint_deposit_tokens(&claim, &mut nullifiers)
        .expect("Minting from verified canonical DepositERC20 log must succeed");
    assert_eq!(new_bal, amount);
    assert_eq!(ledger.get_balance(&token, &recipient), amount);
    assert_eq!(ledger.get_total_supply(&token), amount);

    // Replay rejection
    let replay = ledger.mint_deposit_tokens(&claim, &mut nullifiers);
    assert_eq!(replay.unwrap_err(), ReceiverError::AlreadyClaimed);
}

#[test]
fn test_claim_authenticated_pda_u256_provenance_verification() {
    let mut nullifiers = NullifierSet::new();
    let deposit_contract = [0x42; 20];
    let token = [0xaa; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let amount = 500_000_000_000_000_000_000u128; // 500 tokens

    let statement = make_erc20_deposit_statement(
        ETH_SEPOLIA_CHAIN_ID,
        true,
        amount,
        MOSOO_PROGRAM_ID,
        deposit_contract,
        token,
        sender,
        recipient,
    );

    // 1. Adversary fabricates statement account with fake owner program ID
    let fake_owner = [0x99; 32];
    let fabricated_account = StatementAccount {
        owner: fake_owner,
        pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
        statement: statement.clone(),
    };
    let err =
        claim_authenticated_pda_u256(&fabricated_account, &mut nullifiers, U256::from(100u64))
            .expect_err("Fabricated account with fake owner must be rejected");
    assert_eq!(err, ReceiverError::UnauthenticatedAttester);

    // 2. Adversary fabricates statement account with mismatched PDA address
    let fake_pda = [0x88; 32];
    let tampered_pda_account = StatementAccount {
        owner: MOSOO_PROGRAM_ID,
        pda_address: fake_pda,
        statement: statement.clone(),
    };
    let err2 =
        claim_authenticated_pda_u256(&tampered_pda_account, &mut nullifiers, U256::from(100u64))
            .expect_err("Account with tampered PDA address must be rejected");
    assert_eq!(err2, ReceiverError::UnauthenticatedAttester);

    // 3. Authentic statement account succeeds
    let authentic_account = StatementAccount::new_authentic(statement);
    let minted =
        claim_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
            .expect("Authentic statement account must be accepted");
    assert_eq!(minted, U256::from(amount));

    // 4. Replay rejected
    let replay =
        claim_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
            .expect_err("Replay claim on statement account must be rejected");
    assert_eq!(replay, ReceiverError::AlreadyClaimed);
}

#[test]
fn test_erc20_ledger_authenticated_pda_mint_succeeds_and_fabricated_rejected() {
    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();
    let token = [0x11; 20];
    let sender = [0x22; 20];
    let recipient = [0x33; 32];
    let amount = 1_000_000u128;

    ledger.register_trusted_locker(ETH_SEPOLIA_CHAIN_ID, [0xaa; 20]);
    ledger.allow_token(ETH_SEPOLIA_CHAIN_ID, token);

    let statement = make_erc20_deposit_statement(
        ETH_SEPOLIA_CHAIN_ID,
        true,
        amount,
        MOSOO_PROGRAM_ID,
        [0xaa; 20],
        token,
        sender,
        recipient,
    );

    // 1. Fabricated account rejected
    let fabricated = StatementAccount {
        owner: [0x55; 32],
        pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
        statement: statement.clone(),
    };
    let err = ledger.mint_deposit_authenticated_pda_u256(&fabricated, [0xaa; 20], &mut nullifiers);
    assert_eq!(err, Err(ReceiverError::UnauthenticatedAttester));

    // 2. Zero address bypass strictly rejected
    let authentic = StatementAccount::new_authentic(statement);
    let zero_addr_err =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, [0u8; 20], &mut nullifiers);
    assert_eq!(zero_addr_err, Err(ReceiverError::DepositBackingRequired));

    // 3. Mismatched expected deposit contract rejected
    let mismatch =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xee; 20], &mut nullifiers);
    assert_eq!(
        mismatch,
        Err(ReceiverError::DepositContractMismatch {
            expected: [0xaa; 20],
            actual: [0xee; 20],
        })
    );

    // 4. Authentic account mints tokens successfully
    let minted = ledger
        .mint_deposit_authenticated_pda_u256(&authentic, [0xaa; 20], &mut nullifiers)
        .expect("Authentic StatementAccount PDA mint must succeed");
    assert_eq!(minted, U256::from(amount));
    assert_eq!(ledger.get_balance(&token, &recipient), amount);
    assert_eq!(ledger.get_total_supply(&token), amount);

    // 5. Double-mint replay rejected
    let replay =
        ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xaa; 20], &mut nullifiers);
    assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
}

#[test]
fn test_erc20_mint_deposit_atomic_rejects_unbacked_transfer_proof() {
    use alloy_primitives::{keccak256, Address, U256};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();
    let token_addr = [0x11; 20];
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    let locker_addr = [0xaa; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let amount = U256::from(100_000_000_000_000_000_000u128);

    // Ordinary Transfer event log (NOT DepositERC20 from MosooLocker)
    let receipt_rlp = build_test_eip1559_transfer_receipt(
        Address::from(token_addr),
        Address::from(depositor),
        Address::from([0x44; 20]),
        amount,
    );
    let tx_index: u64 = 0;
    let key_bytes = alloy_rlp::encode(tx_index);
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
        target: ProofTarget::ReceiptLog {
            tx_index,
            log_index: 0,
            emitter: Address::from(token_addr),
            topic0: keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let mut min_32 = [0u8; 32];
    min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: min_32 },
        expected_deposit_contract: locker_addr,
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(1_000u64),
    };

    // Minting deposit strictly rejects ordinary ERC-20 transfer logs!
    let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
    assert_eq!(err, Err(ReceiverError::DepositBackingRequired));
    assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
}

#[test]
fn test_erc20_mint_deposit_atomic_rejects_storage_proof() {
    use alloy_primitives::{Address, B256, U256};
    use mosoo_core::inclusion::test_helpers::build_test_storage_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();
    let token_addr = [0x11; 20];
    let locker_addr = [0xaa; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let recipient = [0x33; 32];

    let contract = Address::from(token_addr);
    let slot = B256::repeat_byte(0x05);
    let mut expected_val = [0u8; 32];
    expected_val[31] = 42;

    let (state_root, account_proof, account_rlp, storage_proof, storage_rlp) =
        build_test_storage_proof(contract, slot, expected_val);

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
        current_receipts_root: [0x99; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x77; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x99; 32],
    };

    let proof = StateProof {
        target: ProofTarget::StorageSlot { contract, slot },
        account_proof,
        storage_proof: Some(storage_proof),
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: Some(storage_rlp),
        receipt_value: None,
    };

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: locker_addr,
        expected_token_contract: token_addr,
        expected_sender: None,
        recipient,
        min_amount: U256::from(1_000u64),
    };

    // Minting deposit strictly rejects raw storage proofs
    let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
    assert_eq!(err, Err(ReceiverError::DepositBackingRequired));
    assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
}

#[test]
fn test_erc20_mint_deposit_atomic_succeeds_with_authentic_locker() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let locker_addr = [0xaa; 20];
    let token_addr = [0x11; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    let amount = U256::from(2_500_000_000_000_000_000u128); // 2.5 tokens
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        Address::from(locker_addr),
        Address::from(token_addr),
        Address::from(depositor),
        recipient,
        amount,
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
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(locker_addr),
            token_contract: Address::from(token_addr),
            sender: Address::from(depositor),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: locker_addr,
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(1_000u64),
    };

    // 1. Authentic deposit mint succeeds
    let minted = ledger
        .mint_deposit_atomic_u256(args.clone(), &mut nullifiers)
        .expect("Authentic atomic deposit mint must succeed");
    assert_eq!(minted, amount);
    assert_eq!(
        ledger.get_balance(&token_addr, &recipient),
        2_500_000_000_000_000_000u128
    );
    assert_eq!(
        ledger.get_total_supply(&token_addr),
        2_500_000_000_000_000_000u128
    );

    // 2. Replay rejected by nullifier
    let replay = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
    assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
}

#[test]
fn test_erc20_mint_deposit_atomic_rejects_malicious_deposit_contract() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let authentic_locker = [0xaa; 20];
    let malicious_locker = [0x99; 20]; // Attacker contract emitting DepositERC20
    let token_addr = [0x11; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    let amount = U256::from(1_000_000_000u64);
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        Address::from(malicious_locker),
        Address::from(token_addr),
        Address::from(depositor),
        recipient,
        amount,
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
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(malicious_locker),
            token_contract: Address::from(token_addr),
            sender: Address::from(depositor),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: authentic_locker, // Expects canonical locker
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(1_000u64),
    };

    // Rejected because deposit_contract does not match expected_deposit_contract!
    let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
    assert_eq!(
        err,
        Err(ReceiverError::DepositContractMismatch {
            expected: authentic_locker,
            actual: malicious_locker,
        })
    );
    assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
    assert_eq!(ledger.get_total_supply(&token_addr), 0);
}

#[test]
fn test_erc20_mint_deposit_atomic_overflow_fails_without_consuming_nullifier() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let locker_addr = [0xaa; 20];
    let token_addr = [0x11; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    // Amount exceeding u128::MAX (2^128)
    let amount = U256::from(u128::MAX) + U256::from(1u64);
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        Address::from(locker_addr),
        Address::from(token_addr),
        Address::from(depositor),
        recipient,
        amount,
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
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(locker_addr),
            token_contract: Address::from(token_addr),
            sender: Address::from(depositor),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: locker_addr,
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(1_000u64),
    };

    let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
    assert_eq!(err, Err(ReceiverError::Overflow));
    // Verify nullifiers remain clean (no burned or orphan nullifier state)
    assert!(!nullifiers.is_used(&[0u8; 32]));
    assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
}

#[test]
fn test_erc20_mint_deposit_atomic_rejects_untrusted_locker_and_zero_address() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let authentic_locker = [0xaa; 20]; // Default Mainnet canonical locker
    let fake_locker = [0x77; 20];
    let token_addr = [0x11; 20];
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    let amount = U256::from(500_000u64);
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        Address::from(authentic_locker),
        Address::from(token_addr),
        Address::from(depositor),
        recipient,
        amount,
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
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(authentic_locker),
            token_contract: Address::from(token_addr),
            sender: Address::from(depositor),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    // 1. Zero address expected_deposit_contract strictly rejected (no bypass)
    let zero_addr_args = AtomicErc20ClaimArgsU256 {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: [0u8; 20],
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(100u64),
    };
    let err_zero = ledger.mint_deposit_atomic_u256(zero_addr_args, &mut nullifiers);
    assert_eq!(err_zero, Err(ReceiverError::DepositBackingRequired));

    // 2. Caller-supplied fake expected locker rejected against program-owned configuration
    let fake_args = AtomicErc20ClaimArgsU256 {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: fake_locker,
        expected_token_contract: token_addr,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(100u64),
    };
    let err_fake = ledger.mint_deposit_atomic_u256(fake_args, &mut nullifiers);
    assert_eq!(
        err_fake,
        Err(ReceiverError::DepositContractMismatch {
            expected: authentic_locker,
            actual: fake_locker,
        })
    );
}

#[test]
fn test_erc20_mint_deposit_atomic_enforces_token_allowlist() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
    use mosoo_core::inclusion::{ProofTarget, StateProof};
    use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

    let mut ledger = Erc20Ledger::new();
    let mut nullifiers = NullifierSet::new();

    let authentic_locker = [0xaa; 20];
    let allowed_token = [0x11; 20];
    let forbidden_token = [0x99; 20];
    let depositor = [0x22; 20];
    let recipient = [0x33; 32];
    let amount = U256::from(500_000u64);
    let nonce = 1u64;

    // Configure allowlist: only allowed_token is permitted on Mainnet
    ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
    ledger.allow_token(ETH_MAINNET_CHAIN_ID, allowed_token);

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        Address::from(authentic_locker),
        Address::from(forbidden_token),
        Address::from(depositor),
        recipient,
        amount,
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
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: Address::from(authentic_locker),
            token_contract: Address::from(forbidden_token),
            sender: Address::from(depositor),
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };

    let forbidden_args = AtomicErc20ClaimArgsU256 {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0u8; 32] },
        expected_deposit_contract: authentic_locker,
        expected_token_contract: forbidden_token,
        expected_sender: Some(depositor),
        recipient,
        min_amount: U256::from(100u64),
    };

    let err = ledger.mint_deposit_atomic_u256(forbidden_args, &mut nullifiers);
    assert_eq!(
        err,
        Err(ReceiverError::TokenNotAllowed(
            forbidden_token,
            ETH_MAINNET_CHAIN_ID
        ))
    );
    assert_eq!(ledger.get_balance(&forbidden_token, &recipient), 0);
}
