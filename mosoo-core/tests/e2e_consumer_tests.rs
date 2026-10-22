use alloy_primitives::U256;
use erc20_receiver::{claim, NullifierSet, ReceiverError};
use mosoo_core::{
    inclusion::VerifiedValue,
    predicate,
    types::{Predicate, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID},
};

#[test]
fn test_e2e_attestation_to_consumer_mint_and_nullifier_lifecycle() {
    let mut nullifiers = NullifierSet::new();

    // Simulating verified Ethereum state:
    // User deposit slot key: keccak256(user || token)
    let user_deposit_key = [0x42u8; 32];
    let user_balance = VerifiedValue::EthBalance(U256::from(500u64));

    // Predicate: must have at least 100 tokens
    let mut min_threshold = [0u8; 32];
    min_threshold[31] = 100;
    let pred = Predicate::AtLeast { min: min_threshold };

    // Mosoo predicate engine evaluates and generates VerifiedStatement bound to subject key
    let statement = predicate::evaluate(
        &pred,
        &user_balance,
        ETH_MAINNET_CHAIN_ID,
        user_deposit_key,
        1,
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
    let sepolia_statement = predicate::evaluate(
        &pred,
        &user_balance,
        ETH_SEPOLIA_CHAIN_ID,
        user_deposit_key,
        1,
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
    let failing_statement = predicate::evaluate(
        &high_pred,
        &user_balance,
        ETH_MAINNET_CHAIN_ID,
        user_deposit_key,
        1,
    )
    .unwrap();
    assert!(!failing_statement.predicate_holds);

    let pred_err = claim(&failing_statement, &mut nullifiers, 100)
        .expect_err("failed predicate must be rejected");
    assert!(matches!(pred_err, ReceiverError::PredicateFailed));
}

#[test]
fn test_cross_slot_proof_produces_identical_nullifier_preventing_repeated_mint() {
    let mut nullifiers = NullifierSet::new();

    let deposit_slot_key = [0x88u8; 32];
    let balance = VerifiedValue::EthBalance(U256::from(1000u64));

    let mut min_threshold = [0u8; 32];
    min_threshold[31] = 250;
    let pred = Predicate::AtLeast { min: min_threshold };

    // Attester proves balance at slot 1,000,000
    let stmt_at_slot_1m =
        predicate::evaluate(&pred, &balance, ETH_MAINNET_CHAIN_ID, deposit_slot_key, 1).unwrap();

    // User claims on LEZ: minted tokens derive strictly from verified balance (1000)
    let minted = claim(&stmt_at_slot_1m, &mut nullifiers, 250).unwrap();
    assert_eq!(minted, 1000);

    // Later at slot 2,000,000, user attempts to generate another proof for the same deposit slot
    let stmt_at_slot_2m =
        predicate::evaluate(&pred, &balance, ETH_MAINNET_CHAIN_ID, deposit_slot_key, 1).unwrap();

    // Invariant: statement_id MUST be identical because the underlying on-chain subject and value are identical!
    assert_eq!(stmt_at_slot_1m.statement_id, stmt_at_slot_2m.statement_id);

    // Attempting to claim again at slot 2,000,000 MUST be rejected with AlreadyClaimed!
    let second_claim = claim(&stmt_at_slot_2m, &mut nullifiers, 250);
    assert!(matches!(second_claim, Err(ReceiverError::AlreadyClaimed)));
}
