#![allow(deprecated)]

use alloy_primitives::U256;
use erc20_receiver::{claim, NullifierSet, ReceiverError};
use ether_receiver::{claim_ether, EtherNullifierSet, EtherReceiverError};
use mosoo_core::{
    inclusion::VerifiedValue,
    predicate::{self, derive_erc20_transfer_subject_key},
    types::{
        Predicate, StatementBinding, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        PROOF_TYPE_ACCOUNT_BALANCE, PROOF_TYPE_ERC20_TRANSFER,
    },
};
use sha2::Digest;

#[test]
fn test_e2e_attestation_to_consumer_mint_and_nullifier_lifecycle() {
    let mut nullifiers = NullifierSet::new();

    let token_contract = [0xaa; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let block_hash = [0x33; 32];
    let slot = 10_000_000u64;
    let tx_index = 0u64;
    let log_index = 0usize;

    let user_deposit_key = derive_erc20_transfer_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &token_contract,
        &sender,
        &recipient,
    );
    let user_balance = VerifiedValue::LogData(U256::from(500u64).to_be_bytes::<32>().to_vec());

    // Predicate: must have at least 100 tokens
    let mut min_threshold = [0u8; 32];
    min_threshold[31] = 100;
    let pred = Predicate::AtLeast { min: min_threshold };

    let binding = StatementBinding::Erc20Transfer {
        execution_block_hash: block_hash,
        slot,
        tx_index,
        log_index,
        token_contract,
        sender,
        recipient,
    };

    // Mosoo predicate engine evaluates and generates VerifiedStatement bound to subject key
    let statement = predicate::evaluate_with_binding(
        &pred,
        &user_balance,
        ETH_MAINNET_CHAIN_ID,
        user_deposit_key,
        PROOF_TYPE_ERC20_TRANSFER,
        binding.clone(),
    )
    .unwrap();

    assert_eq!(statement.chain_id, ETH_MAINNET_CHAIN_ID);
    assert!(statement.predicate_holds);
    assert_ne!(statement.statement_id, [0u8; 32]);

    // Consumer processes the statement: first claim MUST succeed and mint strictly verified amount (500)
    let minted = claim(&statement, &mut nullifiers, 100).expect("first claim should succeed");
    assert_eq!(minted, 500);

    // Duplicate claim attack: submitting the exact same statement again MUST be rejected
    let replay_err = claim(&statement, &mut nullifiers, 100).expect_err("replay must be rejected");
    assert!(matches!(replay_err, ReceiverError::AlreadyClaimed));

    // Cross-chain replay attack: Sepolia statement on mainnet receiver MUST be rejected
    let sepolia_statement = predicate::evaluate_with_binding(
        &pred,
        &user_balance,
        ETH_SEPOLIA_CHAIN_ID,
        user_deposit_key,
        PROOF_TYPE_ERC20_TRANSFER,
        binding.clone(),
    )
    .unwrap();
    let chain_err =
        claim(&sepolia_statement, &mut nullifiers, 100).expect_err("wrong chain must be rejected");
    assert!(matches!(chain_err, ReceiverError::WrongChain(_)));

    // Failing predicate rejected
    let mut high_threshold = [0u8; 32];
    high_threshold[30] = 0x03; // 768 > 500
    high_threshold[31] = 0x00;
    let high_pred = Predicate::AtLeast {
        min: high_threshold,
    };
    let failing_statement = predicate::evaluate_with_binding(
        &high_pred,
        &user_balance,
        ETH_MAINNET_CHAIN_ID,
        user_deposit_key,
        PROOF_TYPE_ERC20_TRANSFER,
        binding,
    )
    .unwrap();
    assert!(!failing_statement.predicate_holds);

    let pred_err = claim(&failing_statement, &mut nullifiers, 100)
        .expect_err("failed predicate must be rejected");
    assert!(matches!(pred_err, ReceiverError::PredicateFailed));
}

#[test]
fn test_cross_slot_proof_produces_identical_nullifier_preventing_repeated_mint() {
    let mut nullifiers = EtherNullifierSet::new();

    let user_addr = [0x42; 20];
    let user_subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();
    let balance = VerifiedValue::EthBalance(U256::from(1000u64));

    let mut min_threshold = [0u8; 32];
    min_threshold[31] = 250;
    let pred = Predicate::AtLeast { min: min_threshold };

    let binding = StatementBinding::Account { address: user_addr };

    // Attester proves balance at slot 1,000,000
    let stmt_at_slot_1m = predicate::evaluate_with_binding(
        &pred,
        &balance,
        ETH_MAINNET_CHAIN_ID,
        user_subject_key,
        PROOF_TYPE_ACCOUNT_BALANCE,
        binding.clone(),
    )
    .unwrap();

    // User claims on LEZ: credited wei derives strictly from verified balance (1000)
    let credited = claim_ether(&stmt_at_slot_1m, &mut nullifiers, 250).unwrap();
    assert_eq!(credited, 1000);

    // Later at slot 2,000,000, user attempts to generate another proof for the same deposit slot
    let stmt_at_slot_2m = predicate::evaluate_with_binding(
        &pred,
        &balance,
        ETH_MAINNET_CHAIN_ID,
        user_subject_key,
        PROOF_TYPE_ACCOUNT_BALANCE,
        binding,
    )
    .unwrap();

    // Invariant: statement_id MUST be identical because the underlying on-chain subject and value are identical!
    assert_eq!(stmt_at_slot_1m.statement_id, stmt_at_slot_2m.statement_id);

    // Attempting to claim again at slot 2,000,000 MUST be rejected with AlreadyClaimed!
    let second_claim = claim_ether(&stmt_at_slot_2m, &mut nullifiers, 250);
    assert!(matches!(
        second_claim,
        Err(EtherReceiverError::AlreadyClaimed)
    ));
}
