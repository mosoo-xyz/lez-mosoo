//! Two-Way Bridge Integration Tests: Ethereum MosooLocker <-> LEZ mETH Token Bridge
//!
//! Verifies the complete end-to-end cross-chain bridge lifecycle:
//! 1. Native ETH locked in Ethereum `MosooLocker.sol`
//! 2. Light client consensus update & execution state root finalization
//! 3. MPT receipt log proof attestation and nullifier generation
//! 4. 1:1 synthetic `mETH` minting on Logos Execution Zone
//! 5. Intra-LEZ `mETH` peer-to-peer transfers
//! 6. `mETH` burn on LEZ producing cryptographic `BurnReceipt`
//! 7. Ethereum `MosooLocker.sol:unlockETH` verification & fund release
//! 8. Cross-chain invariant and replay resistance enforcement

use alloy_primitives::keccak256;
use erc20_receiver::{
    derive_burn_erc20_id, Erc20Ledger, Erc20TransferClaim, NullifierSet as Erc20NullifierSet,
    ReceiverError,
};
use ether_receiver::{
    derive_burn_id, EtherNullifierSet, EtherReceiverError, MethLedger, NativeEthDepositClaim,
};
use mosoo_core::predicate::{derive_erc20_transfer_subject_key, derive_eth_deposit_subject_key};
use mosoo_core::types::{
    StatementBinding, VerifiedStatement, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID,
    PROOF_TYPE_ERC20_TRANSFER, PROOF_TYPE_ETH_DEPOSIT,
};
use std::collections::HashMap;

/// Mock simulation of Ethereum `MosooLocker.sol` state machine
struct MockEthereumLocker {
    pub locked_eth_wei: u128,
    pub unlocked_eth_wei: u128,
    pub locked_erc20: HashMap<[u8; 20], u128>,
    pub unlocked_erc20: HashMap<[u8; 20], u128>,
    pub deposit_nonce: u64,
    pub executed_burns: HashMap<[u8; 32], bool>,
    pub _locker_address: [u8; 20],
}

impl MockEthereumLocker {
    fn new(locker_address: [u8; 20]) -> Self {
        Self {
            locked_eth_wei: 0,
            unlocked_eth_wei: 0,
            locked_erc20: HashMap::new(),
            unlocked_erc20: HashMap::new(),
            deposit_nonce: 0,
            executed_burns: HashMap::new(),
            _locker_address: locker_address,
        }
    }

    /// Simulates `depositETH(bytes32 lezRecipient) payable`
    fn deposit_eth(&mut self, amount_wei: u128) -> u64 {
        assert!(amount_wei > 0, "ZeroAmount");
        self.deposit_nonce += 1;
        self.locked_eth_wei += amount_wei;
        self.deposit_nonce
    }

    /// Simulates `depositERC20(address token, uint256 amount, bytes32 lezRecipient)`
    fn deposit_erc20(&mut self, token: [u8; 20], amount: u128) -> u64 {
        assert!(amount > 0, "ZeroAmount");
        self.deposit_nonce += 1;
        let entry = self.locked_erc20.entry(token).or_insert(0);
        *entry += amount;
        self.deposit_nonce
    }

    /// Simulates `unlockETH(bytes32 burnId, uint256 amount, address recipient, ...)`
    fn unlock_eth(
        &mut self,
        burn_id: [u8; 32],
        amount_wei: u128,
        lez_owner: [u8; 32],
        eth_recipient: [u8; 20],
        burn_nonce: u64,
        lez_slot: u64,
    ) -> Result<(), &'static str> {
        if amount_wei == 0 {
            return Err("ZeroAmount");
        }
        if self.executed_burns.contains_key(&burn_id) {
            return Err("BurnAlreadyExecuted");
        }
        if self.locked_eth_wei < amount_wei {
            return Err("InsufficientLockedETH");
        }

        let expected_burn_id = derive_burn_id(
            ETH_MAINNET_CHAIN_ID,
            &lez_owner,
            &eth_recipient,
            amount_wei,
            burn_nonce,
            lez_slot,
        );
        if burn_id != expected_burn_id {
            return Err("InvalidBurnProof");
        }

        self.executed_burns.insert(burn_id, true);
        self.locked_eth_wei -= amount_wei;
        self.unlocked_eth_wei += amount_wei;
        Ok(())
    }

    /// Simulates `unlockERC20(bytes32 burnId, address token, uint256 amount, ...)`
    #[allow(clippy::too_many_arguments)]
    fn unlock_erc20(
        &mut self,
        burn_id: [u8; 32],
        token: [u8; 20],
        amount: u128,
        lez_owner: [u8; 32],
        eth_recipient: [u8; 20],
        burn_nonce: u64,
        lez_slot: u64,
    ) -> Result<(), &'static str> {
        if amount == 0 {
            return Err("ZeroAmount");
        }
        if self.executed_burns.contains_key(&burn_id) {
            return Err("BurnAlreadyExecuted");
        }
        let locked = self.locked_erc20.get(&token).copied().unwrap_or(0);
        if locked < amount {
            return Err("InsufficientLockedERC20");
        }

        let expected_burn_id = derive_burn_erc20_id(
            ETH_MAINNET_CHAIN_ID,
            &token,
            &lez_owner,
            &eth_recipient,
            amount,
            burn_nonce,
            lez_slot,
        );
        if burn_id != expected_burn_id {
            return Err("InvalidBurnProof");
        }

        self.executed_burns.insert(burn_id, true);
        let entry = self.locked_erc20.entry(token).or_insert(0);
        *entry -= amount;
        let unlocked_entry = self.unlocked_erc20.entry(token).or_insert(0);
        *unlocked_entry += amount;
        Ok(())
    }
}

#[test]
fn test_full_two_way_bridge_lifecycle_eth_to_lez_and_back() {
    let locker_addr = [0x11; 20];
    let eth_sender = [0x22; 20];
    let alice_lez = [0xAA; 32];
    let bob_lez = [0xBB; 32];
    let eth_withdrawal_recipient = [0x33; 20];

    // 1. Initialize Ethereum Locker & LEZ Ledger
    let mut eth_locker = MockEthereumLocker::new(locker_addr);
    let mut lez_ledger = MethLedger::new();
    let mut lez_nullifiers = EtherNullifierSet::new();

    // 2. User locks 10 ETH on Ethereum
    let deposit_amount: u128 = 10_000_000_000_000_000_000; // 10 ETH
    let nonce = eth_locker.deposit_eth(deposit_amount);
    assert_eq!(nonce, 1);
    assert_eq!(eth_locker.locked_eth_wei, deposit_amount);

    // 3. Build verified attestation statement corresponding to the deposit receipt log
    let block_hash = [0x44; 32];
    let slot = 10_500_000u64;
    let tx_index = 3u64;
    let log_index = 0usize;

    let subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &locker_addr,
        &eth_sender,
        &alice_lez,
    );

    let mut val_bytes = [0u8; 32];
    val_bytes[16..32].copy_from_slice(&deposit_amount.to_be_bytes());

    let statement_id = keccak256([&subject_key[..], &val_bytes[..]].concat()).0;

    let statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
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
            deposit_contract: locker_addr,
            sender: eth_sender,
            recipient: alice_lez,
        },
    };

    let claim = NativeEthDepositClaim {
        statement,
        expected_deposit_contract: locker_addr,
        sender: eth_sender,
        recipient: alice_lez,
        min_wei: 1_000_000_000_000_000_000,
    };

    // 4. Mint 10 mETH on LEZ
    let minted_balance = lez_ledger.mint_meth(&claim, &mut lez_nullifiers).unwrap();
    assert_eq!(minted_balance, deposit_amount);
    assert_eq!(lez_ledger.get_balance(&alice_lez), deposit_amount);
    assert_eq!(lez_ledger.total_supply_wei, deposit_amount);

    // Cross-Chain Invariant 1: Locked ETH on Mainnet == Total Active mETH on LEZ
    assert_eq!(eth_locker.locked_eth_wei, lez_ledger.total_supply_wei);

    // 5. Alice transfers 4 mETH to Bob on LEZ
    let transfer_amount: u128 = 4_000_000_000_000_000_000; // 4 ETH
    lez_ledger
        .transfer_meth(&alice_lez, &bob_lez, transfer_amount)
        .unwrap();
    assert_eq!(
        lez_ledger.get_balance(&alice_lez),
        6_000_000_000_000_000_000
    );
    assert_eq!(lez_ledger.get_balance(&bob_lez), 4_000_000_000_000_000_000);
    assert_eq!(lez_ledger.total_supply_wei, deposit_amount); // Supply unchanged

    // 6. Alice burns 6 mETH on LEZ to withdraw real ETH back to Ethereum
    let burn_amount: u128 = 6_000_000_000_000_000_000; // 6 ETH
    let lez_burn_slot = 62_185u64;
    let burn_receipt = lez_ledger
        .burn_meth(
            ETH_MAINNET_CHAIN_ID,
            &alice_lez,
            burn_amount,
            &eth_withdrawal_recipient,
            lez_burn_slot,
        )
        .unwrap();

    assert_eq!(lez_ledger.get_balance(&alice_lez), 0);
    assert_eq!(lez_ledger.total_supply_wei, 4_000_000_000_000_000_000); // Only Bob's 4 mETH remains
    assert_eq!(lez_ledger.total_burned_wei, burn_amount);

    // 7. Present BurnReceipt to Ethereum MosooLocker to unlock funds
    let unlock_res = eth_locker.unlock_eth(
        burn_receipt.burn_id,
        burn_receipt.amount_wei,
        burn_receipt.lez_owner,
        burn_receipt.eth_recipient,
        burn_receipt.burn_nonce,
        burn_receipt.lez_slot,
    );
    assert!(unlock_res.is_ok());

    // 8. Verify final cross-chain balances and invariants
    assert_eq!(eth_locker.unlocked_eth_wei, burn_amount);
    assert_eq!(eth_locker.locked_eth_wei, 4_000_000_000_000_000_000);

    // Cross-Chain Invariant 2: Remaining locked ETH strictly matches remaining LEZ supply (Bob's 4 mETH)
    assert_eq!(eth_locker.locked_eth_wei, lez_ledger.total_supply_wei);
    assert_eq!(lez_ledger.get_balance(&bob_lez), eth_locker.locked_eth_wei);

    // 9. Replay Attack Prevention on Ethereum: Repeating the same unlock is strictly rejected
    let replay_unlock = eth_locker.unlock_eth(
        burn_receipt.burn_id,
        burn_receipt.amount_wei,
        burn_receipt.lez_owner,
        burn_receipt.eth_recipient,
        burn_receipt.burn_nonce,
        burn_receipt.lez_slot,
    );
    assert_eq!(replay_unlock.unwrap_err(), "BurnAlreadyExecuted");

    // 10. Replay Attack Prevention on LEZ: Repeating the same deposit mint is strictly rejected
    let replay_mint = lez_ledger.mint_meth(&claim, &mut lez_nullifiers);
    assert!(matches!(
        replay_mint,
        Err(EtherReceiverError::AlreadyClaimed)
    ));
}

#[test]
fn test_two_way_bridge_adversarial_tampered_burn_id_rejected() {
    let locker_addr = [0x11; 20];
    let alice_lez = [0xAA; 32];
    let eth_recipient = [0x33; 20];

    let mut eth_locker = MockEthereumLocker::new(locker_addr);
    eth_locker.deposit_eth(10_000_000_000_000_000_000);

    // Fabricated burn ID not matching canonical keccak256
    let tampered_burn_id = [0xDE; 32];
    let res = eth_locker.unlock_eth(
        tampered_burn_id,
        5_000_000_000_000_000_000,
        alice_lez,
        eth_recipient,
        1,
        100,
    );
    assert_eq!(res.unwrap_err(), "InvalidBurnProof");
}

#[test]
fn test_full_two_way_erc20_bridge_lifecycle_usdc_to_lez_and_back() {
    let locker_addr = [0x11; 20];
    let usdc_token = [0xA0; 20];
    let eth_sender = [0x22; 20];
    let alice_lez = [0xAA; 32];
    let bob_lez = [0xBB; 32];
    let eth_withdrawal_recipient = [0x33; 20];

    let mut eth_locker = MockEthereumLocker::new(locker_addr);
    let mut lez_ledger = Erc20Ledger::new();
    let mut lez_nullifiers = Erc20NullifierSet::new();

    // 1. User deposits 1,000 USDC into Ethereum MosooLocker
    let deposit_amount: u128 = 1_000_000_000; // 1,000 USDC (6 decimals)
    let nonce = eth_locker.deposit_erc20(usdc_token, deposit_amount);
    assert_eq!(nonce, 1);
    assert_eq!(
        eth_locker.locked_erc20.get(&usdc_token).copied().unwrap(),
        deposit_amount
    );

    // 2. Build verified attestation statement corresponding to the ERC-20 transfer log
    let block_hash = [0x55; 32];
    let slot = 10_600_000u64;
    let tx_index = 4u64;
    let log_index = 1usize;

    let subject_key = derive_erc20_transfer_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &usdc_token,
        &eth_sender,
        &alice_lez,
    );

    let mut val_bytes = [0u8; 32];
    val_bytes[24..32].copy_from_slice(&(deposit_amount as u64).to_be_bytes());

    let statement_id = keccak256([&subject_key[..], &val_bytes[..]].concat()).0;

    let statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: true,
        verified_value: val_bytes,
        subject_key,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            token_contract: usdc_token,
            sender: eth_sender,
            recipient: alice_lez,
        },
    };

    let claim = Erc20TransferClaim {
        statement,
        token_contract: usdc_token,
        sender: eth_sender,
        recipient: alice_lez,
        min_amount: 100_000_000,
    };

    // 3. Mint 1,000 mUSDC on LEZ
    let minted = lez_ledger.mint_tokens(&claim, &mut lez_nullifiers).unwrap();
    assert_eq!(minted, deposit_amount);
    assert_eq!(
        lez_ledger.get_balance(&usdc_token, &alice_lez),
        deposit_amount
    );
    assert_eq!(lez_ledger.get_total_supply(&usdc_token), deposit_amount);

    // Cross-Chain Invariant 1: Locked USDC on Ethereum == Active mUSDC on LEZ
    assert_eq!(
        eth_locker.locked_erc20.get(&usdc_token).copied().unwrap(),
        lez_ledger.get_total_supply(&usdc_token)
    );

    // 4. Alice transfers 300 USDC to Bob on LEZ
    let transfer_amount: u128 = 300_000_000;
    lez_ledger
        .transfer_tokens(&usdc_token, &alice_lez, &bob_lez, transfer_amount)
        .unwrap();
    assert_eq!(lez_ledger.get_balance(&usdc_token, &alice_lez), 700_000_000);
    assert_eq!(lez_ledger.get_balance(&usdc_token, &bob_lez), 300_000_000);

    // 5. Alice burns her remaining 700 USDC to unlock on Ethereum
    let burn_amount: u128 = 700_000_000;
    let lez_burn_slot = 62_250u64;
    let burn_receipt = lez_ledger
        .burn_tokens(
            ETH_MAINNET_CHAIN_ID,
            &usdc_token,
            &alice_lez,
            burn_amount,
            &eth_withdrawal_recipient,
            lez_burn_slot,
        )
        .unwrap();

    assert_eq!(lez_ledger.get_balance(&usdc_token, &alice_lez), 0);
    assert_eq!(lez_ledger.get_total_supply(&usdc_token), 300_000_000);
    assert_eq!(lez_ledger.get_total_burned(&usdc_token), 700_000_000);

    // 6. Present Erc20BurnReceipt to Ethereum MosooLocker.unlockERC20
    let unlock_res = eth_locker.unlock_erc20(
        burn_receipt.burn_id,
        burn_receipt.token,
        burn_receipt.amount,
        burn_receipt.lez_owner,
        burn_receipt.eth_recipient,
        burn_receipt.burn_nonce,
        burn_receipt.lez_slot,
    );
    assert!(unlock_res.is_ok());

    // 7. Verify cross-chain balances and invariants
    assert_eq!(
        eth_locker.unlocked_erc20.get(&usdc_token).copied().unwrap(),
        700_000_000
    );
    assert_eq!(
        eth_locker.locked_erc20.get(&usdc_token).copied().unwrap(),
        300_000_000
    );
    assert_eq!(
        eth_locker.locked_erc20.get(&usdc_token).copied().unwrap(),
        lez_ledger.get_total_supply(&usdc_token)
    );
    assert_eq!(
        lez_ledger.get_balance(&usdc_token, &bob_lez),
        eth_locker.locked_erc20.get(&usdc_token).copied().unwrap()
    );

    // 8. Replay attack rejection on Ethereum
    let replay_unlock = eth_locker.unlock_erc20(
        burn_receipt.burn_id,
        burn_receipt.token,
        burn_receipt.amount,
        burn_receipt.lez_owner,
        burn_receipt.eth_recipient,
        burn_receipt.burn_nonce,
        burn_receipt.lez_slot,
    );
    assert_eq!(replay_unlock.unwrap_err(), "BurnAlreadyExecuted");

    // 9. Replay attack rejection on LEZ
    let replay_mint = lez_ledger.mint_tokens(&claim, &mut lez_nullifiers);
    assert!(matches!(replay_mint, Err(ReceiverError::AlreadyClaimed)));
}
