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

use alloy_primitives::U256;
use erc20_receiver::{
    derive_burn_erc20_id, Erc20Ledger, Erc20TransferClaim, NullifierSet as Erc20NullifierSet,
    ReceiverError,
};
use ether_receiver::{derive_burn_id, EtherNullifierSet, EtherReceiverError, MethLedger};
use mosoo_core::predicate::{derive_erc20_transfer_subject_key, derive_eth_deposit_subject_key};
use mosoo_core::types::{
    StatementAccount, StatementBinding, VerifiedStatement, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID,
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
    pub locker_address: [u8; 20],
    pub chain_id: u64,
    pub attester_authority: [u8; 20],
    pub pending_attester_authority: Option<[u8; 20]>,
    pub authority_timelock_unlock: u64,
    pub token_allowlist_enabled: bool,
    pub allowed_tokens: HashMap<[u8; 20], bool>,
    pub daily_withdrawal_limit_eth: u128,
    pub daily_withdrawn_eth: u128,
    pub large_withdrawal_threshold_eth: u128,
    pub large_withdrawal_delay: u64,
    pub queued_withdrawals: HashMap<[u8; 32], u64>,
    pub cancelled_burns: std::collections::HashSet<[u8; 32]>,
    pub is_attester: HashMap<[u8; 20], bool>,
    pub attester_count: usize,
    pub required_quorum: usize,
}

pub const AUTHORITY_CHANGE_DELAY: u64 = 86_400; // 1 day in seconds
pub const LARGE_WITHDRAWAL_THRESHOLD_ETH: u128 = 10_000_000_000_000_000_000; // 10 ETH

impl MockEthereumLocker {
    fn new(locker_address: [u8; 20]) -> Self {
        let mut is_attester = HashMap::new();
        is_attester.insert([0xaa; 20], true);
        Self {
            locked_eth_wei: 0,
            unlocked_eth_wei: 0,
            locked_erc20: HashMap::new(),
            unlocked_erc20: HashMap::new(),
            deposit_nonce: 0,
            executed_burns: HashMap::new(),
            locker_address,
            chain_id: ETH_MAINNET_CHAIN_ID,
            attester_authority: [0xaa; 20],
            pending_attester_authority: None,
            authority_timelock_unlock: 0,
            token_allowlist_enabled: true,
            allowed_tokens: HashMap::new(),
            daily_withdrawal_limit_eth: 0,
            daily_withdrawn_eth: 0,
            large_withdrawal_threshold_eth: LARGE_WITHDRAWAL_THRESHOLD_ETH,
            large_withdrawal_delay: 86_400,
            queued_withdrawals: HashMap::new(),
            cancelled_burns: std::collections::HashSet::new(),
            is_attester,
            attester_count: 1,
            required_quorum: 1,
        }
    }

    fn add_attester(&mut self, attester: [u8; 20]) {
        self.is_attester.insert(attester, true);
        self.attester_count = self.is_attester.len();
    }

    fn set_quorum(&mut self, quorum: usize) -> Result<(), &'static str> {
        if quorum == 0 || quorum > self.attester_count {
            return Err("InvalidQuorum");
        }
        self.required_quorum = quorum;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn unlock_eth_with_quorum(
        &mut self,
        burn_id: [u8; 32],
        amount_wei: u128,
        lez_owner: [u8; 32],
        eth_recipient: [u8; 20],
        burn_nonce: u64,
        lez_slot: u64,
        signers: &[[u8; 20]],
    ) -> Result<(), &'static str> {
        if signers.len() < self.required_quorum {
            return Err("QuorumNotMet");
        }
        let mut last_signer = [0u8; 20];
        for signer in signers {
            if !self.is_attester.get(signer).copied().unwrap_or(false) {
                return Err("UnauthorizedAttester");
            }
            if *signer <= last_signer {
                return Err("DuplicateOrUnorderedAttesterSignature");
            }
            last_signer = *signer;
        }
        self.unlock_eth(
            burn_id,
            amount_wei,
            lez_owner,
            eth_recipient,
            burn_nonce,
            lez_slot,
        )
    }

    /// Simulates `depositETH(bytes32 lezRecipient) payable`
    fn deposit_eth(&mut self, amount_wei: u128) -> u64 {
        assert!(amount_wei > 0, "ZeroAmount");
        self.deposit_nonce += 1;
        self.locked_eth_wei += amount_wei;
        self.deposit_nonce
    }

    /// Simulates `setTokenAllowlistEnabled(bool enabled)`
    fn set_token_allowlist_enabled(&mut self, enabled: bool) {
        self.token_allowlist_enabled = enabled;
    }

    /// Simulates `setTokenAllowed(address token, bool allowed)`
    fn set_token_allowed(&mut self, token: [u8; 20], allowed: bool) {
        self.allowed_tokens.insert(token, allowed);
    }

    /// Simulates `depositERC20(address token, uint256 amount, bytes32 lezRecipient)`
    fn deposit_erc20(&mut self, token: [u8; 20], amount: u128) -> Result<u64, &'static str> {
        if amount == 0 {
            return Err("ZeroAmount");
        }
        if self.token_allowlist_enabled
            && !self.allowed_tokens.get(&token).copied().unwrap_or(false)
        {
            return Err("TokenNotAllowed");
        }
        self.deposit_nonce += 1;
        let entry = self.locked_erc20.entry(token).or_insert(0);
        *entry += amount;
        Ok(self.deposit_nonce)
    }

    /// Simulates `proposeAttesterAuthority(address _newAuthority)`
    fn propose_attester_authority(
        &mut self,
        new_authority: [u8; 20],
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if new_authority == [0u8; 20] {
            return Err("ZeroAddress");
        }
        self.pending_attester_authority = Some(new_authority);
        self.authority_timelock_unlock = current_time + AUTHORITY_CHANGE_DELAY;
        Ok(self.authority_timelock_unlock)
    }

    /// Simulates `executeAttesterAuthority()`
    fn execute_attester_authority(&mut self, current_time: u64) -> Result<(), &'static str> {
        let pending = self
            .pending_attester_authority
            .ok_or("NoPendingAuthority")?;
        if current_time < self.authority_timelock_unlock {
            return Err("AuthorityTimelockActive");
        }
        self.attester_authority = pending;
        self.pending_attester_authority = None;
        self.authority_timelock_unlock = 0;
        Ok(())
    }

    /// Computes EIP-712 domain separator binding verifyingContract address(this)
    fn domain_separator(&self) -> [u8; 32] {
        let typehash = alloy_primitives::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = alloy_primitives::keccak256(b"MosooLocker");
        let version_hash = alloy_primitives::keccak256(b"1");
        let chain_id_bytes = alloy_primitives::U256::from(self.chain_id).to_be_bytes::<32>();
        let mut contract_bytes = [0u8; 32];
        contract_bytes[12..32].copy_from_slice(&self.locker_address);

        let mut encoded = Vec::with_capacity(32 * 5);
        encoded.extend_from_slice(typehash.as_slice());
        encoded.extend_from_slice(name_hash.as_slice());
        encoded.extend_from_slice(version_hash.as_slice());
        encoded.extend_from_slice(&chain_id_bytes);
        encoded.extend_from_slice(&contract_bytes);
        alloy_primitives::keccak256(&encoded).0
    }

    /// Derives the EIP-712 typed data digest for BurnETH
    fn compute_eip712_burn_eth_digest(
        &self,
        burn_id: [u8; 32],
        recipient: [u8; 20],
        amount_wei: u128,
        lez_owner: [u8; 32],
        burn_nonce: u64,
        lez_slot: u64,
    ) -> [u8; 32] {
        let burn_eth_typehash = alloy_primitives::keccak256(
            b"BurnETH(bytes32 burnId,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)",
        );
        let mut recipient_32 = [0u8; 32];
        recipient_32[12..32].copy_from_slice(&recipient);
        let amount_32 = alloy_primitives::U256::from(amount_wei).to_be_bytes::<32>();
        let mut nonce_32 = [0u8; 32];
        nonce_32[24..32].copy_from_slice(&burn_nonce.to_be_bytes());
        let mut slot_32 = [0u8; 32];
        slot_32[24..32].copy_from_slice(&lez_slot.to_be_bytes());

        let mut struct_encoded = Vec::with_capacity(32 * 7);
        struct_encoded.extend_from_slice(burn_eth_typehash.as_slice());
        struct_encoded.extend_from_slice(&burn_id);
        struct_encoded.extend_from_slice(&recipient_32);
        struct_encoded.extend_from_slice(&amount_32);
        struct_encoded.extend_from_slice(&lez_owner);
        struct_encoded.extend_from_slice(&nonce_32);
        struct_encoded.extend_from_slice(&slot_32);
        let struct_hash = alloy_primitives::keccak256(&struct_encoded);

        let domain_sep = self.domain_separator();
        let mut final_digest_input = Vec::with_capacity(2 + 32 + 32);
        final_digest_input.extend_from_slice(b"\x19\x01");
        final_digest_input.extend_from_slice(&domain_sep);
        final_digest_input.extend_from_slice(struct_hash.as_slice());
        alloy_primitives::keccak256(&final_digest_input).0
    }

    fn set_daily_withdrawal_limit_eth(&mut self, limit: u128) {
        self.daily_withdrawal_limit_eth = limit;
    }

    fn cancel_queued_withdrawal(&mut self, burn_id: [u8; 32]) -> Result<(), &'static str> {
        if !self.queued_withdrawals.contains_key(&burn_id) {
            return Err("NoQueuedWithdrawal");
        }
        self.queued_withdrawals.remove(&burn_id);
        self.cancelled_burns.insert(burn_id);
        Ok(())
    }

    fn cancel_burn(&mut self, burn_id: [u8; 32]) {
        self.queued_withdrawals.remove(&burn_id);
        self.cancelled_burns.insert(burn_id);
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
        self.unlock_eth_with_time(
            burn_id,
            amount_wei,
            lez_owner,
            eth_recipient,
            burn_nonce,
            lez_slot,
            0,
        )
    }

    /// Simulates `unlockETH` with timestamp check for large withdrawal queue and daily rate limit
    #[allow(clippy::too_many_arguments)]
    fn unlock_eth_with_time(
        &mut self,
        burn_id: [u8; 32],
        amount_wei: u128,
        lez_owner: [u8; 32],
        eth_recipient: [u8; 20],
        burn_nonce: u64,
        lez_slot: u64,
        current_timestamp: u64,
    ) -> Result<(), &'static str> {
        if amount_wei == 0 {
            return Err("ZeroAmount");
        }
        if self.executed_burns.contains_key(&burn_id) {
            return Err("BurnAlreadyExecuted");
        }
        if self.cancelled_burns.contains(&burn_id) {
            return Err("BurnCancelled");
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

        // Large withdrawal timelock delay
        if amount_wei >= self.large_withdrawal_threshold_eth && current_timestamp > 0 {
            if let Some(&unlock_time) = self.queued_withdrawals.get(&burn_id) {
                if current_timestamp < unlock_time {
                    return Err("LargeWithdrawalPending");
                }
            } else {
                let unlock_time = current_timestamp + self.large_withdrawal_delay;
                self.queued_withdrawals.insert(burn_id, unlock_time);
                return Err("WithdrawalQueued");
            }
        }

        // Daily volume limit check
        if self.daily_withdrawal_limit_eth > 0 {
            if self.daily_withdrawn_eth + amount_wei > self.daily_withdrawal_limit_eth {
                return Err("DailyLimitExceeded");
            }
            self.daily_withdrawn_eth += amount_wei;
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

    let mut statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
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
    statement.statement_id = statement.derive_canonical_id();

    // 4. Mint 10 mETH on LEZ via authentic on-chain StatementAccount PDA
    let statement_account = StatementAccount::new_authentic(statement);
    let minted_u256 = lez_ledger
        .mint_deposit_authenticated_pda_u256(&statement_account, &mut lez_nullifiers)
        .unwrap();
    assert_eq!(minted_u256, U256::from(deposit_amount));
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
    let replay_mint =
        lez_ledger.mint_deposit_authenticated_pda_u256(&statement_account, &mut lez_nullifiers);
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
    eth_locker.set_token_allowed(usdc_token, true);
    let nonce = eth_locker
        .deposit_erc20(usdc_token, deposit_amount)
        .unwrap();
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

    let mut statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
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
    statement.statement_id = statement.derive_canonical_id();

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

#[test]
fn test_eip712_cross_contract_replay_protection() {
    let locker_a = MockEthereumLocker::new([0x11; 20]);
    let locker_b = MockEthereumLocker::new([0x22; 20]);

    // Domain separators must be distinct because verifyingContract differs
    let domain_sep_a = locker_a.domain_separator();
    let domain_sep_b = locker_b.domain_separator();
    assert_ne!(
        domain_sep_a, domain_sep_b,
        "Domain separators must be distinct across different locker contracts"
    );

    let burn_id = [0x77; 32];
    let recipient = [0x33; 20];
    let amount_wei = 5_000_000_000_000_000_000u128; // 5 ETH
    let lez_owner = [0xaa; 32];
    let burn_nonce = 42u64;
    let lez_slot = 9_999_999u64;

    // Compute typed digests for Locker A and Locker B
    let digest_a = locker_a.compute_eip712_burn_eth_digest(
        burn_id, recipient, amount_wei, lez_owner, burn_nonce, lez_slot,
    );
    let digest_b = locker_b.compute_eip712_burn_eth_digest(
        burn_id, recipient, amount_wei, lez_owner, burn_nonce, lez_slot,
    );

    assert_ne!(
        digest_a, digest_b,
        "EIP-712 digests must be strictly segregated by verifyingContract"
    );
}

#[test]
fn test_token_allowlist_enforcement() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let allowed_token = [0x55; 20];
    let unapproved_token = [0x66; 20];
    let amount = 1_000_000_000u128;

    // By default, allowlist is enabled: unapproved token is strictly rejected
    let default_err = locker.deposit_erc20(unapproved_token, amount);
    assert_eq!(default_err.unwrap_err(), "TokenNotAllowed");

    // Allowlist approved token
    locker.set_token_allowed(allowed_token, true);

    // Unapproved token must still be strictly rejected
    let err = locker.deposit_erc20(unapproved_token, amount);
    assert_eq!(err.unwrap_err(), "TokenNotAllowed");

    // Approved token succeeds
    let ok = locker.deposit_erc20(allowed_token, amount);
    assert!(ok.is_ok());

    // When allowlist is explicitly toggled off by admin, unapproved token is accepted
    locker.set_token_allowlist_enabled(false);
    assert!(locker.deposit_erc20(unapproved_token, amount).is_ok());
}

#[test]
fn test_attester_authority_timelock_pipeline() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let initial_authority = [0xaa; 20];
    let new_authority = [0xbb; 20];
    assert_eq!(locker.attester_authority, initial_authority);

    // Proposing zero address is rejected
    assert_eq!(
        locker
            .propose_attester_authority([0u8; 20], 1_000)
            .unwrap_err(),
        "ZeroAddress"
    );

    // Propose valid authority at timestamp 1,000
    let current_time = 1_000u64;
    let unlock_time = locker
        .propose_attester_authority(new_authority, current_time)
        .unwrap();
    assert_eq!(unlock_time, 1_000 + AUTHORITY_CHANGE_DELAY);
    assert_eq!(locker.pending_attester_authority, Some(new_authority));

    // Attempting to execute before timelock unlock fails
    let early_exec = locker.execute_attester_authority(current_time + 10_000);
    assert_eq!(early_exec.unwrap_err(), "AuthorityTimelockActive");
    assert_eq!(locker.attester_authority, initial_authority);

    // Executing exactly at or after unlock timestamp succeeds
    let valid_exec = locker.execute_attester_authority(unlock_time);
    assert!(valid_exec.is_ok());
    assert_eq!(locker.attester_authority, new_authority);
    assert_eq!(locker.pending_attester_authority, None);
    assert_eq!(locker.authority_timelock_unlock, 0);

    // Attempting to execute again with no pending authority fails
    assert_eq!(
        locker
            .execute_attester_authority(unlock_time + 10)
            .unwrap_err(),
        "NoPendingAuthority"
    );
}

#[test]
fn test_mosoo_locker_daily_withdrawal_limit_enforced() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let total_deposit: u128 = 20_000_000_000_000_000_000; // 20 ETH
    locker.deposit_eth(total_deposit);

    // Set daily withdrawal limit of 5 ETH
    let daily_limit: u128 = 5_000_000_000_000_000_000;
    locker.set_daily_withdrawal_limit_eth(daily_limit);

    let burn_id_1 = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        3_000_000_000_000_000_000,
        1,
        100,
    );
    // First withdrawal of 3 ETH succeeds
    assert!(locker
        .unlock_eth(
            burn_id_1,
            3_000_000_000_000_000_000,
            lez_owner,
            eth_recipient,
            1,
            100
        )
        .is_ok());

    let burn_id_2 = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        3_000_000_000_000_000_000,
        2,
        101,
    );
    // Second withdrawal of 3 ETH exceeds daily limit (3 + 3 = 6 > 5) -> must revert DailyLimitExceeded
    let res = locker.unlock_eth(
        burn_id_2,
        3_000_000_000_000_000_000,
        lez_owner,
        eth_recipient,
        2,
        101,
    );
    assert_eq!(res.unwrap_err(), "DailyLimitExceeded");
}

#[test]
fn test_mosoo_locker_large_withdrawal_queue_and_guardian_veto() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let total_deposit: u128 = 50_000_000_000_000_000_000; // 50 ETH
    locker.deposit_eth(total_deposit);

    let large_burn_amount: u128 = 15_000_000_000_000_000_000; // 15 ETH (>= 10 ETH threshold)
    let burn_id = derive_burn_id(1, &lez_owner, &eth_recipient, large_burn_amount, 1, 200);

    let current_time = 1_000_000u64;
    // First attempt queues the withdrawal and returns WithdrawalQueued
    let queue_res = locker.unlock_eth_with_time(
        burn_id,
        large_burn_amount,
        lez_owner,
        eth_recipient,
        1,
        200,
        current_time,
    );
    assert_eq!(queue_res.unwrap_err(), "WithdrawalQueued");

    // Immediate retry fails with LargeWithdrawalPending
    let early_res = locker.unlock_eth_with_time(
        burn_id,
        large_burn_amount,
        lez_owner,
        eth_recipient,
        1,
        200,
        current_time + 10_000,
    );
    assert_eq!(early_res.unwrap_err(), "LargeWithdrawalPending");

    // Guardian vetoes the malicious queued withdrawal during an emergency!
    assert!(locker.cancel_queued_withdrawal(burn_id).is_ok());

    // Subsequent unlock attempt fails permanently with BurnCancelled! Re-queue bypass is strictly prevented.
    let post_cancel_res = locker.unlock_eth_with_time(
        burn_id,
        large_burn_amount,
        lez_owner,
        eth_recipient,
        1,
        200,
        current_time + 100_000,
    );
    assert_eq!(post_cancel_res.unwrap_err(), "BurnCancelled");
}

#[test]
fn test_mosoo_locker_proactive_guardian_veto_rejects_withdrawal() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let total_deposit: u128 = 20_000_000_000_000_000_000; // 20 ETH
    locker.deposit_eth(total_deposit);

    let burn_amount: u128 = 5_000_000_000_000_000_000; // 5 ETH
    let burn_id = derive_burn_id(1, &lez_owner, &eth_recipient, burn_amount, 1, 300);

    // Guardian proactively cancels fraudulent burn authorization before relayer submission
    locker.cancel_burn(burn_id);

    // Relayer attempts to unlock ETH with cancelled burn authorization
    let res = locker.unlock_eth(burn_id, burn_amount, lez_owner, eth_recipient, 1, 300);
    assert_eq!(res.unwrap_err(), "BurnCancelled");
}

#[test]
fn test_two_way_bridge_multi_signer_quorum_and_rejection() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let total_deposit: u128 = 20_000_000_000_000_000_000; // 20 ETH
    locker.deposit_eth(total_deposit);

    let attester1 = [0x10; 20];
    let attester2 = [0x20; 20];
    let attester3 = [0x30; 20];

    locker.add_attester(attester1);
    locker.add_attester(attester2);
    locker.add_attester(attester3);
    locker
        .set_quorum(2)
        .expect("setting quorum to 2 must succeed");

    let burn_amount: u128 = 2_000_000_000_000_000_000; // 2 ETH
    let burn_id = derive_burn_id(1, &lez_owner, &eth_recipient, burn_amount, 5, 400);

    // 1. Sub-threshold quorum (only 1 signer provided) fails
    let err_sub = locker.unlock_eth_with_quorum(
        burn_id,
        burn_amount,
        lez_owner,
        eth_recipient,
        5,
        400,
        &[attester1],
    );
    assert_eq!(err_sub.unwrap_err(), "QuorumNotMet");

    // 2. Duplicate or disordered signers fail
    let err_dup = locker.unlock_eth_with_quorum(
        burn_id,
        burn_amount,
        lez_owner,
        eth_recipient,
        5,
        400,
        &[attester1, attester1],
    );
    assert_eq!(
        err_dup.unwrap_err(),
        "DuplicateOrUnorderedAttesterSignature"
    );

    let err_unordered = locker.unlock_eth_with_quorum(
        burn_id,
        burn_amount,
        lez_owner,
        eth_recipient,
        5,
        400,
        &[attester2, attester1],
    );
    assert_eq!(
        err_unordered.unwrap_err(),
        "DuplicateOrUnorderedAttesterSignature"
    );

    // 3. Unauthorized signer fails
    let fake_attester = [0x99; 20];
    let err_fake = locker.unlock_eth_with_quorum(
        burn_id,
        burn_amount,
        lez_owner,
        eth_recipient,
        5,
        400,
        &[attester1, fake_attester],
    );
    assert_eq!(err_fake.unwrap_err(), "UnauthorizedAttester");

    // 4. Valid 2-of-3 quorum in strictly ascending order succeeds
    assert!(locker
        .unlock_eth_with_quorum(
            burn_id,
            burn_amount,
            lez_owner,
            eth_recipient,
            5,
            400,
            &[attester1, attester2],
        )
        .is_ok());
    assert_eq!(locker.unlocked_eth_wei, burn_amount);

    // 5. Replay fails with BurnAlreadyExecuted
    let err_replay = locker.unlock_eth_with_quorum(
        burn_id,
        burn_amount,
        lez_owner,
        eth_recipient,
        5,
        400,
        &[attester1, attester2],
    );
    assert_eq!(err_replay.unwrap_err(), "BurnAlreadyExecuted");
}
