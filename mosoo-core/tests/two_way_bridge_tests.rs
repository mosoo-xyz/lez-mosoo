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
    derive_burn_erc20_id, derive_burn_erc20_id_v2, Erc20Ledger, Erc20TransferClaim,
    NullifierSet as Erc20NullifierSet, ReceiverError,
};
use ether_receiver::{
    derive_burn_id, derive_burn_id_v2, EtherNullifierSet, EtherReceiverError, MethLedger,
};
use mosoo_core::predicate::{derive_erc20_transfer_subject_key, derive_eth_deposit_subject_key};
use mosoo_core::types::{
    StatementAccount, StatementBinding, VerifiedStatement, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID,
    PROOF_TYPE_ERC20_TRANSFER, PROOF_TYPE_ETH_DEPOSIT,
};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub struct WithdrawalRecord {
    pub timestamp: u64,
    pub amount: u128,
}

pub const GOVERNANCE_TIMELOCK_DELAY: u64 = 172_800; // 2 days in seconds
pub const MAX_CLEANUP_BATCH: usize = 32;
pub const MAX_PASS2_CLEANUP_BATCH: usize = 128;

/// Mock simulation of Ethereum `MosooLocker.sol` state machine
struct MockEthereumLocker {
    pub owner: [u8; 20],
    pub guardian: [u8; 20],
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
    pub eth_withdrawals: Vec<WithdrawalRecord>,
    pub eth_withdrawal_head: usize,
    pub rolling_withdrawn_eth: u128,
    pub erc20_withdrawals: HashMap<[u8; 20], Vec<WithdrawalRecord>>,
    pub erc20_withdrawal_head: HashMap<[u8; 20], usize>,
    pub rolling_withdrawn_erc20: HashMap<[u8; 20], u128>,
    pub daily_withdrawal_limit_erc20: HashMap<[u8; 20], u128>,
    pub pending_daily_withdrawal_limit_eth: Option<u128>,
    pub daily_withdrawal_limit_eth_timelock_unlock: u64,
    pub pending_daily_withdrawal_limit_erc20: HashMap<[u8; 20], u128>,
    pub daily_withdrawal_limit_erc20_timelock_unlock: HashMap<[u8; 20], u64>,
    pub large_withdrawal_threshold_eth: u128,
    pub large_withdrawal_delay: u64,
    pub queued_withdrawals: HashMap<[u8; 32], u64>,
    pub cancelled_burns: std::collections::HashSet<[u8; 32]>,
    pub is_attester: HashMap<[u8; 20], bool>,
    pub attester_count: usize,
    pub required_quorum: usize,
    pub pending_quorum: Option<usize>,
    pub quorum_timelock_unlock: u64,
    pub pending_add_attester: Option<[u8; 20]>,
    pub add_attester_timelock_unlock: u64,
    pub pending_remove_attester: Option<[u8; 20]>,
    pub remove_attester_timelock_unlock: u64,
    pub pending_guardian: Option<[u8; 20]>,
    pub guardian_timelock_unlock: u64,
}

pub const AUTHORITY_CHANGE_DELAY: u64 = 86_400; // 1 day in seconds
pub const LARGE_WITHDRAWAL_THRESHOLD_ETH: u128 = 10_000_000_000_000_000_000; // 10 ETH

impl MockEthereumLocker {
    fn new(locker_address: [u8; 20]) -> Self {
        Self::new_with_guardian(locker_address, [0xee; 20])
    }

    fn new_with_guardian(locker_address: [u8; 20], guardian: [u8; 20]) -> Self {
        let mut is_attester = HashMap::new();
        is_attester.insert([0xaa; 20], true);
        Self {
            owner: [0xee; 20],
            guardian,
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
            eth_withdrawals: Vec::new(),
            eth_withdrawal_head: 0,
            rolling_withdrawn_eth: 0,
            erc20_withdrawals: HashMap::new(),
            erc20_withdrawal_head: HashMap::new(),
            rolling_withdrawn_erc20: HashMap::new(),
            daily_withdrawal_limit_erc20: HashMap::new(),
            pending_daily_withdrawal_limit_eth: None,
            daily_withdrawal_limit_eth_timelock_unlock: 0,
            pending_daily_withdrawal_limit_erc20: HashMap::new(),
            daily_withdrawal_limit_erc20_timelock_unlock: HashMap::new(),
            large_withdrawal_threshold_eth: LARGE_WITHDRAWAL_THRESHOLD_ETH,
            large_withdrawal_delay: 86_400,
            queued_withdrawals: HashMap::new(),
            cancelled_burns: std::collections::HashSet::new(),
            is_attester,
            attester_count: 1,
            required_quorum: 1,
            pending_quorum: None,
            quorum_timelock_unlock: 0,
            pending_add_attester: None,
            add_attester_timelock_unlock: 0,
            pending_remove_attester: None,
            remove_attester_timelock_unlock: 0,
            pending_guardian: None,
            guardian_timelock_unlock: 0,
        }
    }

    fn add_attester(&mut self, attester: [u8; 20]) {
        self.is_attester.insert(attester, true);
        self.attester_count = self.is_attester.len();
    }

    fn propose_quorum(
        &mut self,
        new_quorum: usize,
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if new_quorum == 0 || new_quorum > self.attester_count {
            return Err("InvalidQuorum");
        }
        self.pending_quorum = Some(new_quorum);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.quorum_timelock_unlock = unlock;
        Ok(unlock)
    }

    fn execute_quorum(&mut self, current_time: u64) -> Result<usize, &'static str> {
        let proposed = self.pending_quorum.ok_or("NoPendingGovernanceAction")?;
        if current_time < self.quorum_timelock_unlock {
            return Err("GovernanceTimelockActive");
        }
        if proposed > self.attester_count {
            return Err("InvalidQuorum");
        }
        self.required_quorum = proposed;
        self.pending_quorum = None;
        self.quorum_timelock_unlock = 0;
        Ok(proposed)
    }

    fn propose_add_attester(
        &mut self,
        attester: [u8; 20],
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if attester == [0u8; 20] {
            return Err("ZeroAddress");
        }
        if self.is_attester.get(&attester).copied().unwrap_or(false) {
            return Err("AttesterAlreadyExists");
        }
        self.pending_add_attester = Some(attester);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.add_attester_timelock_unlock = unlock;
        Ok(unlock)
    }

    fn execute_add_attester(&mut self, current_time: u64) -> Result<[u8; 20], &'static str> {
        let proposed = self
            .pending_add_attester
            .ok_or("NoPendingGovernanceAction")?;
        if current_time < self.add_attester_timelock_unlock {
            return Err("GovernanceTimelockActive");
        }
        if self.is_attester.get(&proposed).copied().unwrap_or(false) {
            return Err("AttesterAlreadyExists");
        }
        self.is_attester.insert(proposed, true);
        self.attester_count = self.is_attester.len();
        self.pending_add_attester = None;
        self.add_attester_timelock_unlock = 0;
        Ok(proposed)
    }

    fn propose_remove_attester(
        &mut self,
        attester: [u8; 20],
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if !self.is_attester.get(&attester).copied().unwrap_or(false) {
            return Err("AttesterNotFound");
        }
        if self.attester_count <= 1 || self.attester_count - 1 < self.required_quorum {
            return Err("InvalidQuorum");
        }
        self.pending_remove_attester = Some(attester);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.remove_attester_timelock_unlock = unlock;
        Ok(unlock)
    }

    fn execute_remove_attester(&mut self, current_time: u64) -> Result<[u8; 20], &'static str> {
        let proposed = self
            .pending_remove_attester
            .ok_or("NoPendingGovernanceAction")?;
        if current_time < self.remove_attester_timelock_unlock {
            return Err("GovernanceTimelockActive");
        }
        if !self.is_attester.get(&proposed).copied().unwrap_or(false) {
            return Err("AttesterNotFound");
        }
        if self.attester_count <= 1 || self.attester_count - 1 < self.required_quorum {
            return Err("InvalidQuorum");
        }
        self.is_attester.remove(&proposed);
        self.attester_count = self.is_attester.len();
        if proposed == self.attester_authority {
            self.attester_authority = [0u8; 20];
        }
        self.pending_remove_attester = None;
        self.remove_attester_timelock_unlock = 0;
        Ok(proposed)
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
        let old_authority = self.attester_authority;
        let new_authority = pending;

        let mut projected_count = self.attester_count;
        if old_authority != new_authority {
            if self
                .is_attester
                .get(&old_authority)
                .copied()
                .unwrap_or(false)
            {
                projected_count -= 1;
            }
            if !self
                .is_attester
                .get(&new_authority)
                .copied()
                .unwrap_or(false)
            {
                projected_count += 1;
            }
        }

        if projected_count < self.required_quorum {
            return Err("InvalidQuorum");
        }

        if old_authority != new_authority {
            self.is_attester.remove(&old_authority);
            self.is_attester.insert(new_authority, true);
            self.attester_count = projected_count;
        }
        self.attester_authority = new_authority;
        self.pending_attester_authority = None;
        self.authority_timelock_unlock = 0;
        Ok(())
    }

    fn cancel_pending_governance(
        &mut self,
        caller: [u8; 20],
        action_type: u8,
    ) -> Result<(), &'static str> {
        if caller != self.owner && caller != self.guardian {
            return Err("Unauthorized");
        }
        match action_type {
            1 => {
                self.pending_quorum = None;
                self.quorum_timelock_unlock = 0;
            }
            2 => {
                self.pending_add_attester = None;
                self.add_attester_timelock_unlock = 0;
            }
            3 => {
                self.pending_remove_attester = None;
                self.remove_attester_timelock_unlock = 0;
            }
            4 => {
                self.pending_daily_withdrawal_limit_eth = None;
                self.daily_withdrawal_limit_eth_timelock_unlock = 0;
            }
            5 => {
                self.pending_guardian = None;
                self.guardian_timelock_unlock = 0;
            }
            6 => {
                self.pending_attester_authority = None;
                self.authority_timelock_unlock = 0;
            }
            _ => return Err("NoPendingGovernanceAction"),
        }
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

    fn propose_daily_withdrawal_limit_eth(
        &mut self,
        new_limit: u128,
        current_time: u64,
    ) -> Result<u64, &'static str> {
        self.pending_daily_withdrawal_limit_eth = Some(new_limit);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.daily_withdrawal_limit_eth_timelock_unlock = unlock;
        Ok(unlock)
    }

    fn execute_daily_withdrawal_limit_eth(
        &mut self,
        current_time: u64,
    ) -> Result<u128, &'static str> {
        let proposed = self
            .pending_daily_withdrawal_limit_eth
            .ok_or("NoPendingGovernanceAction")?;
        if current_time < self.daily_withdrawal_limit_eth_timelock_unlock {
            return Err("GovernanceTimelockActive");
        }
        self.daily_withdrawal_limit_eth = proposed;
        self.pending_daily_withdrawal_limit_eth = None;
        self.daily_withdrawal_limit_eth_timelock_unlock = 0;
        Ok(proposed)
    }

    fn propose_daily_withdrawal_limit_erc20(
        &mut self,
        token: [u8; 20],
        new_limit: u128,
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if token == [0u8; 20] {
            return Err("ZeroAddress");
        }
        self.pending_daily_withdrawal_limit_erc20
            .insert(token, new_limit);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.daily_withdrawal_limit_erc20_timelock_unlock
            .insert(token, unlock);
        Ok(unlock)
    }

    fn execute_daily_withdrawal_limit_erc20(
        &mut self,
        token: [u8; 20],
        current_time: u64,
    ) -> Result<u128, &'static str> {
        if token == [0u8; 20] {
            return Err("ZeroAddress");
        }
        let proposed = self
            .pending_daily_withdrawal_limit_erc20
            .get(&token)
            .copied()
            .ok_or("NoPendingGovernanceAction")?;
        let unlock = self
            .daily_withdrawal_limit_erc20_timelock_unlock
            .get(&token)
            .copied()
            .unwrap_or(0);
        if current_time < unlock {
            return Err("GovernanceTimelockActive");
        }
        self.pending_daily_withdrawal_limit_erc20.remove(&token);
        self.daily_withdrawal_limit_erc20_timelock_unlock
            .remove(&token);
        self.daily_withdrawal_limit_erc20.insert(token, proposed);
        Ok(proposed)
    }

    fn set_daily_withdrawal_limit_eth(&mut self, _limit: u128) -> Result<(), &'static str> {
        Err("DirectGovernanceDeprecated")
    }

    fn set_daily_withdrawal_limit_erc20(
        &mut self,
        _token: [u8; 20],
        _limit: u128,
    ) -> Result<(), &'static str> {
        Err("DirectGovernanceDeprecated")
    }

    fn propose_guardian(
        &mut self,
        caller: [u8; 20],
        new_guardian: [u8; 20],
        current_time: u64,
    ) -> Result<u64, &'static str> {
        if caller != self.owner {
            return Err("Unauthorized");
        }
        if new_guardian == [0u8; 20] {
            return Err("ZeroAddress");
        }
        self.pending_guardian = Some(new_guardian);
        let unlock = current_time + GOVERNANCE_TIMELOCK_DELAY;
        self.guardian_timelock_unlock = unlock;
        Ok(unlock)
    }

    fn execute_guardian(
        &mut self,
        caller: [u8; 20],
        current_time: u64,
    ) -> Result<[u8; 20], &'static str> {
        if caller != self.owner {
            return Err("Unauthorized");
        }
        let proposed = self.pending_guardian.ok_or("NoPendingGovernanceAction")?;
        if current_time < self.guardian_timelock_unlock {
            return Err("GovernanceTimelockActive");
        }
        self.pending_guardian = None;
        self.guardian_timelock_unlock = 0;
        self.guardian = proposed;
        Ok(proposed)
    }

    fn set_guardian(&mut self, _new_guardian: [u8; 20]) -> Result<(), &'static str> {
        Err("DirectGovernanceDeprecated")
    }

    fn cancel_burn_by(&mut self, caller: [u8; 20], burn_id: [u8; 32]) -> Result<(), &'static str> {
        if caller != self.owner && caller != self.guardian {
            return Err("Unauthorized");
        }
        self.queued_withdrawals.remove(&burn_id);
        self.cancelled_burns.insert(burn_id);
        Ok(())
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

        // Single-signer authorization: attesterAuthority must be an active attester in committee
        if self.required_quorum == 1
            && !self
                .is_attester
                .get(&self.attester_authority)
                .copied()
                .unwrap_or(false)
        {
            return Err("UnauthorizedAttester");
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

        // Continuous rolling 24-hour volume limit check (Finding M-04 / 3 hardening)
        if self.daily_withdrawal_limit_eth > 0 {
            let cutoff = current_timestamp.saturating_sub(86_400);
            let mut cleaned = 0;
            // Pass 1: Bounded cleanup for normal gas efficiency
            while self.eth_withdrawal_head < self.eth_withdrawals.len()
                && self.eth_withdrawals[self.eth_withdrawal_head].timestamp < cutoff
                && cleaned < MAX_CLEANUP_BATCH
            {
                self.rolling_withdrawn_eth = self
                    .rolling_withdrawn_eth
                    .saturating_sub(self.eth_withdrawals[self.eth_withdrawal_head].amount);
                self.eth_withdrawal_head += 1;
                cleaned += 1;
            }

            // Pass 2: If limit is threatened, prune expired records up to MAX_PASS2_CLEANUP_BATCH
            if self.rolling_withdrawn_eth + amount_wei > self.daily_withdrawal_limit_eth {
                let mut pass2_cleaned = 0;
                while self.eth_withdrawal_head < self.eth_withdrawals.len()
                    && self.eth_withdrawals[self.eth_withdrawal_head].timestamp < cutoff
                    && pass2_cleaned < MAX_PASS2_CLEANUP_BATCH
                {
                    self.rolling_withdrawn_eth = self
                        .rolling_withdrawn_eth
                        .saturating_sub(self.eth_withdrawals[self.eth_withdrawal_head].amount);
                    self.eth_withdrawal_head += 1;
                    pass2_cleaned += 1;
                }
            }

            if self.rolling_withdrawn_eth + amount_wei > self.daily_withdrawal_limit_eth {
                return Err("DailyLimitExceeded");
            }

            self.rolling_withdrawn_eth += amount_wei;
            self.eth_withdrawals.push(WithdrawalRecord {
                timestamp: current_timestamp,
                amount: amount_wei,
            });
            self.daily_withdrawn_eth = self.rolling_withdrawn_eth;
        }

        self.executed_burns.insert(burn_id, true);
        self.locked_eth_wei -= amount_wei;
        self.unlocked_eth_wei += amount_wei;
        Ok(())
    }

    /// Simulates `unlockERC20` with continuous 24h rolling rate limit
    #[allow(clippy::too_many_arguments)]
    fn unlock_erc20_with_time(
        &mut self,
        burn_id: [u8; 32],
        token: [u8; 20],
        amount: u128,
        lez_owner: [u8; 32],
        eth_recipient: [u8; 20],
        burn_nonce: u64,
        lez_slot: u64,
        current_timestamp: u64,
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

        if let Some(&limit) = self.daily_withdrawal_limit_erc20.get(&token) {
            if limit > 0 {
                let cutoff = current_timestamp.saturating_sub(86_400);
                let head = self.erc20_withdrawal_head.entry(token).or_insert(0);
                let history = self.erc20_withdrawals.entry(token).or_default();
                let rolling = self.rolling_withdrawn_erc20.entry(token).or_insert(0);
                let mut cleaned = 0;

                while *head < history.len()
                    && history[*head].timestamp < cutoff
                    && cleaned < MAX_CLEANUP_BATCH
                {
                    *rolling = rolling.saturating_sub(history[*head].amount);
                    *head += 1;
                    cleaned += 1;
                }

                // Pass 2: If limit is threatened, prune expired records up to MAX_PASS2_CLEANUP_BATCH
                if *rolling + amount > limit {
                    let mut pass2_cleaned = 0;
                    while *head < history.len()
                        && history[*head].timestamp < cutoff
                        && pass2_cleaned < MAX_PASS2_CLEANUP_BATCH
                    {
                        *rolling = rolling.saturating_sub(history[*head].amount);
                        *head += 1;
                        pass2_cleaned += 1;
                    }
                }

                if *rolling + amount > limit {
                    return Err("DailyLimitExceeded");
                }

                *rolling += amount;
                history.push(WithdrawalRecord {
                    timestamp: current_timestamp,
                    amount,
                });
            }
        }

        self.executed_burns.insert(burn_id, true);
        let entry = self.locked_erc20.entry(token).or_insert(0);
        *entry -= amount;
        let unlocked_entry = self.unlocked_erc20.entry(token).or_insert(0);
        *unlocked_entry += amount;
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
        self.unlock_erc20_with_time(
            burn_id,
            token,
            amount,
            lez_owner,
            eth_recipient,
            burn_nonce,
            lez_slot,
            0,
        )
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
    lez_ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
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
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
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
        .mint_deposit_authenticated_pda_u256(&statement_account, locker_addr, &mut lez_nullifiers)
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
    let replay_mint = lez_ledger.mint_deposit_authenticated_pda_u256(
        &statement_account,
        locker_addr,
        &mut lez_nullifiers,
    );
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
#[allow(deprecated)]
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
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
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

    // Set daily withdrawal limit of 5 ETH via timelocked governance
    let daily_limit: u128 = 5_000_000_000_000_000_000;
    assert_eq!(
        locker.set_daily_withdrawal_limit_eth(daily_limit),
        Err("DirectGovernanceDeprecated")
    );
    let unlock_ts = locker
        .propose_daily_withdrawal_limit_eth(daily_limit, 0)
        .unwrap();
    assert_eq!(
        locker
            .execute_daily_withdrawal_limit_eth(unlock_ts)
            .unwrap(),
        daily_limit
    );

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

#[test]
fn test_mosoo_locker_midnight_boundary_rolling_limit_enforced() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let total_deposit: u128 = 20_000_000_000_000_000_000; // 20 ETH
    locker.deposit_eth(total_deposit);

    // Daily withdrawal limit = 5 ETH via timelocked governance
    let daily_limit: u128 = 5_000_000_000_000_000_000;
    assert_eq!(
        locker.set_daily_withdrawal_limit_eth(daily_limit),
        Err("DirectGovernanceDeprecated")
    );
    let unlock_ts = locker
        .propose_daily_withdrawal_limit_eth(daily_limit, 0)
        .unwrap();
    assert_eq!(
        locker
            .execute_daily_withdrawal_limit_eth(unlock_ts)
            .unwrap(),
        daily_limit
    );

    // 1. Withdrawal of 3 ETH at 23:59:59 of Day 1 (timestamp 86399)
    let burn_id_1 = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        3_000_000_000_000_000_000,
        1,
        100,
    );
    let res1 = locker.unlock_eth_with_time(
        burn_id_1,
        3_000_000_000_000_000_000,
        lez_owner,
        eth_recipient,
        1,
        100,
        86399,
    );
    assert!(
        res1.is_ok(),
        "First withdrawal of 3 ETH at 23:59:59 must succeed"
    );

    // 2. Withdrawal of 3 ETH at 00:00:01 of Day 2 (timestamp 86401, 2 seconds later)
    // Under calendar-day / 1 days, this would have reset to 0 and bypassed the limit!
    // Under continuous rolling 24-hour window, 86399 is within [86401 - 86400, 86401], so limit is strictly enforced!
    let burn_id_2 = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        3_000_000_000_000_000_000,
        2,
        101,
    );
    let res2 = locker.unlock_eth_with_time(
        burn_id_2,
        3_000_000_000_000_000_000,
        lez_owner,
        eth_recipient,
        2,
        101,
        86401,
    );
    assert_eq!(
        res2.unwrap_err(),
        "DailyLimitExceeded",
        "Midnight boundary attack (2 seconds later) must be strictly rejected under rolling 24h window"
    );

    // 3. Withdrawal after 24 full hours have elapsed (timestamp 172800 > 86399 + 86400)
    // Old withdrawal at 86399 is pruned and new withdrawal of 3 ETH succeeds!
    let burn_id_3 = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        3_000_000_000_000_000_000,
        3,
        102,
    );
    let res3 = locker.unlock_eth_with_time(
        burn_id_3,
        3_000_000_000_000_000_000,
        lez_owner,
        eth_recipient,
        3,
        102,
        172800,
    );
    assert!(
        res3.is_ok(),
        "Withdrawal after 24h rolling window expires must succeed"
    );
}

#[test]
fn test_mosoo_locker_quorum_timelock_governance() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let attester1 = [0x10; 20];
    let attester2 = [0x20; 20];
    locker.add_attester(attester1);
    locker.add_attester(attester2);
    assert_eq!(locker.required_quorum, 1);

    let current_time = 1_000_000u64;
    // 1. Propose quorum change from 1 to 2
    let unlock_time = locker
        .propose_quorum(2, current_time)
        .expect("proposing quorum 2 must succeed");
    assert_eq!(unlock_time, current_time + GOVERNANCE_TIMELOCK_DELAY);

    // 2. Early execution attempt before timelock expires strictly fails
    let early_res = locker.execute_quorum(current_time + 10_000);
    assert_eq!(early_res.unwrap_err(), "GovernanceTimelockActive");
    assert_eq!(locker.required_quorum, 1);

    // 3. Execution after 2-day timelock delay succeeds
    let exec_res = locker.execute_quorum(unlock_time);
    assert_eq!(exec_res.unwrap(), 2);
    assert_eq!(locker.required_quorum, 2);
    assert_eq!(locker.pending_quorum, None);
}

#[test]
fn test_mosoo_locker_attester_timelock_governance() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    assert_eq!(locker.attester_count, 1);

    let new_attester = [0x77; 20];
    let current_time = 500_000u64;

    // 1. Propose adding new attester
    let unlock_time = locker
        .propose_add_attester(new_attester, current_time)
        .expect("proposing attester must succeed");
    assert_eq!(unlock_time, current_time + GOVERNANCE_TIMELOCK_DELAY);

    // 2. Early execution attempt fails
    let early_res = locker.execute_add_attester(current_time + 100);
    assert_eq!(early_res.unwrap_err(), "GovernanceTimelockActive");
    assert_eq!(locker.attester_count, 1);

    // 3. Execution after timelock delay succeeds
    let ok_res = locker.execute_add_attester(unlock_time);
    assert_eq!(ok_res.unwrap(), new_attester);
    assert_eq!(locker.attester_count, 2);
    assert!(locker.is_attester.get(&new_attester).copied().unwrap());

    // 4. Propose removing the attester
    let remove_unlock = locker
        .propose_remove_attester(new_attester, unlock_time + 10)
        .expect("proposing removal must succeed");
    assert_eq!(remove_unlock, unlock_time + 10 + GOVERNANCE_TIMELOCK_DELAY);

    // 5. Early removal fails
    let early_remove = locker.execute_remove_attester(unlock_time + 100);
    assert_eq!(early_remove.unwrap_err(), "GovernanceTimelockActive");
    assert_eq!(locker.attester_count, 2);

    // 6. Removal after timelock succeeds
    let ok_remove = locker.execute_remove_attester(remove_unlock);
    assert_eq!(ok_remove.unwrap(), new_attester);
    assert_eq!(locker.attester_count, 1);
    assert!(!locker
        .is_attester
        .get(&new_attester)
        .copied()
        .unwrap_or(false));
}

#[test]
fn test_mosoo_locker_erc20_rolling_limit_enforced() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let token = [0x55; 20];
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    let initial_locked: u128 = 100_000 * 1_000_000;
    locker.locked_erc20.insert(token, initial_locked);

    let daily_limit: u128 = 10_000 * 1_000_000;
    assert_eq!(
        locker.set_daily_withdrawal_limit_erc20(token, daily_limit),
        Err("DirectGovernanceDeprecated")
    );
    let unlock_ts = locker
        .propose_daily_withdrawal_limit_erc20(token, daily_limit, 0)
        .unwrap();
    assert_eq!(
        locker
            .execute_daily_withdrawal_limit_erc20(token, unlock_ts)
            .unwrap(),
        daily_limit
    );

    // 1. Withdrawal of 6,000 at timestamp 86399 succeeds
    let burn_id_1 = derive_burn_erc20_id(
        1,
        &token,
        &lez_owner,
        &eth_recipient,
        6_000 * 1_000_000,
        1,
        100,
    );
    assert!(locker
        .unlock_erc20_with_time(
            burn_id_1,
            token,
            6_000 * 1_000_000,
            lez_owner,
            eth_recipient,
            1,
            100,
            86399,
        )
        .is_ok());

    // 2. Withdrawal of 6,000 at timestamp 86401 (2 seconds later) exceeds limit (6k + 6k = 12k > 10k)
    let burn_id_2 = derive_burn_erc20_id(
        1,
        &token,
        &lez_owner,
        &eth_recipient,
        6_000 * 1_000_000,
        2,
        101,
    );
    let res2 = locker.unlock_erc20_with_time(
        burn_id_2,
        token,
        6_000 * 1_000_000,
        lez_owner,
        eth_recipient,
        2,
        101,
        86401,
    );
    assert_eq!(res2.unwrap_err(), "DailyLimitExceeded");

    // 3. Withdrawal after 24 hours (timestamp 172800) succeeds
    let burn_id_3 = derive_burn_erc20_id(
        1,
        &token,
        &lez_owner,
        &eth_recipient,
        6_000 * 1_000_000,
        3,
        102,
    );
    assert!(locker
        .unlock_erc20_with_time(
            burn_id_3,
            token,
            6_000 * 1_000_000,
            lez_owner,
            eth_recipient,
            3,
            102,
            172800,
        )
        .is_ok());
}

#[test]
fn test_mosoo_locker_rate_limit_timelock_governance() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let token = [0x55; 20];

    // 1. Direct rate-limit modification must revert with DirectGovernanceDeprecated
    assert_eq!(
        locker.set_daily_withdrawal_limit_eth(100),
        Err("DirectGovernanceDeprecated")
    );
    assert_eq!(
        locker.set_daily_withdrawal_limit_erc20(token, 100),
        Err("DirectGovernanceDeprecated")
    );

    // 2. Propose ETH rate-limit adjustment (e.g. lowering or setting to 0)
    let current_time = 1_000_000;
    let unlock_ts = locker
        .propose_daily_withdrawal_limit_eth(50_000_000_000_000_000_000, current_time)
        .expect("Propose ETH limit failed");
    assert_eq!(unlock_ts, current_time + GOVERNANCE_TIMELOCK_DELAY);

    // 3. Premature execution must fail
    let err_premature = locker.execute_daily_withdrawal_limit_eth(current_time + 100);
    assert_eq!(err_premature.unwrap_err(), "GovernanceTimelockActive");

    // 4. Execution at or after unlock timestamp succeeds
    let res = locker.execute_daily_withdrawal_limit_eth(unlock_ts);
    assert_eq!(res.unwrap(), 50_000_000_000_000_000_000);
    assert_eq!(
        locker.daily_withdrawal_limit_eth,
        50_000_000_000_000_000_000
    );

    // 5. Test ERC-20 timelocked rate-limit administration
    let erc20_unlock_ts = locker
        .propose_daily_withdrawal_limit_erc20(token, 25_000 * 1_000_000, current_time)
        .expect("Propose ERC20 limit failed");
    assert_eq!(erc20_unlock_ts, current_time + GOVERNANCE_TIMELOCK_DELAY);

    assert_eq!(
        locker
            .execute_daily_withdrawal_limit_erc20(token, current_time + 1_000)
            .unwrap_err(),
        "GovernanceTimelockActive"
    );
    let erc20_res = locker.execute_daily_withdrawal_limit_erc20(token, erc20_unlock_ts);
    assert_eq!(erc20_res.unwrap(), 25_000 * 1_000_000);
    assert_eq!(
        locker
            .daily_withdrawal_limit_erc20
            .get(&token)
            .copied()
            .unwrap(),
        25_000 * 1_000_000
    );
}

#[test]
fn test_mosoo_locker_independent_guardian_veto() {
    let guardian = [0x99; 20];
    let mut locker = MockEthereumLocker::new_with_guardian([0x11; 20], guardian);
    let rogue_actor = [0x42; 20];
    let burn_id = [0x77; 32];

    // Queue a withdrawal
    locker.queued_withdrawals.insert(burn_id, 100_000);

    // Rogue actor tries to cancel burn -> Unauthorized
    assert_eq!(
        locker.cancel_burn_by(rogue_actor, burn_id),
        Err("Unauthorized")
    );
    assert!(!locker.cancelled_burns.contains(&burn_id));

    // Independent Guardian executes veto -> Succeeds
    assert!(locker.cancel_burn_by(guardian, burn_id).is_ok());
    assert!(locker.cancelled_burns.contains(&burn_id));
    assert!(!locker.queued_withdrawals.contains_key(&burn_id));
}

#[test]
fn test_mosoo_locker_bounded_pruning_gas_defense() {
    let mut locker = MockEthereumLocker::new([0x11; 20]);
    let lez_owner = [0xAA; 32];
    let eth_recipient = [0x33; 20];
    locker.deposit_eth(100_000_000_000_000_000_000);

    // Set daily limit to 10 ETH via timelock
    let unlock_ts = locker
        .propose_daily_withdrawal_limit_eth(10_000_000_000_000_000_000, 0)
        .unwrap();
    locker
        .execute_daily_withdrawal_limit_eth(unlock_ts)
        .unwrap();

    // Insert 50 expired withdrawal records (more than MAX_CLEANUP_BATCH = 32)
    let expired_timestamp = 100;
    for i in 0..50 {
        locker.eth_withdrawals.push(WithdrawalRecord {
            timestamp: expired_timestamp + i,
            amount: 10_000_000_000_000_000, // 0.01 ETH
        });
        locker.rolling_withdrawn_eth += 10_000_000_000_000_000;
    }
    assert_eq!(locker.eth_withdrawal_head, 0);
    assert_eq!(locker.eth_withdrawals.len(), 50);

    // Perform withdrawal after 2 days (timestamp = 200,000)
    let burn_id = derive_burn_id(
        1,
        &lez_owner,
        &eth_recipient,
        1_000_000_000_000_000_000,
        1,
        100,
    );
    let res = locker.unlock_eth_with_time(
        burn_id,
        1_000_000_000_000_000_000,
        lez_owner,
        eth_recipient,
        1,
        100,
        200_000,
    );
    assert!(res.is_ok());

    // Verify bounded cleanup: head only advanced by MAX_CLEANUP_BATCH (32), NOT all 50
    assert_eq!(locker.eth_withdrawal_head, MAX_CLEANUP_BATCH);
    assert_eq!(locker.eth_withdrawal_head, 32);
}

#[test]
fn test_mosoo_locker_guardian_timelock_governance() {
    let locker_addr = [0x11; 20];
    let owner = [0xee; 20];
    let initial_guardian = [0x99; 20];
    let new_guardian = [0x88; 20];
    let mut locker = MockEthereumLocker::new_with_guardian(locker_addr, initial_guardian);

    // Direct set_guardian is deprecated and rejected
    assert_eq!(
        locker.set_guardian(new_guardian),
        Err("DirectGovernanceDeprecated")
    );

    // Proposing zero address is rejected
    assert_eq!(
        locker.propose_guardian(owner, [0u8; 20], 1000),
        Err("ZeroAddress")
    );

    // Non-owner cannot propose guardian
    assert_eq!(
        locker.propose_guardian([0x12; 20], new_guardian, 1000),
        Err("Unauthorized")
    );

    // Owner proposes valid new guardian
    let unlock = locker
        .propose_guardian(owner, new_guardian, 1000)
        .expect("propose failed");
    assert_eq!(unlock, 1000 + GOVERNANCE_TIMELOCK_DELAY);

    // Premature execution fails
    assert_eq!(
        locker.execute_guardian(owner, unlock - 1),
        Err("GovernanceTimelockActive")
    );

    // Execution after timelock succeeds
    let executed = locker
        .execute_guardian(owner, unlock)
        .expect("execute failed");
    assert_eq!(executed, new_guardian);
    assert_eq!(locker.guardian, new_guardian);
    assert_eq!(locker.pending_guardian, None);
}

#[test]
fn test_removed_attester_single_signature_rejected() {
    let locker_addr = [0x77; 20];
    let mut locker = MockEthereumLocker::new(locker_addr);
    let attester2 = [0xbb; 20];

    // Add attester2
    locker
        .propose_add_attester(attester2, 1000)
        .expect("propose add");
    locker
        .execute_add_attester(1000 + GOVERNANCE_TIMELOCK_DELAY)
        .expect("exec add");

    // Rotate authority to attester2
    locker
        .propose_attester_authority(attester2, 200_000)
        .expect("propose authority");
    locker
        .execute_attester_authority(200_000 + AUTHORITY_CHANGE_DELAY)
        .expect("exec authority");

    assert_eq!(locker.attester_authority, attester2);
    assert!(!locker
        .is_attester
        .get(&[0xaa; 20])
        .copied()
        .unwrap_or(false));

    // Old authority removed, so attempts to withdraw under old authority are rejected
    locker.deposit_eth(10_000_000_000_000_000_000);
    let lez_owner = [0x55; 32];
    let recipient = [0x88; 20];
    let amount = 1_000_000_000_000_000_000;
    let burn_id = derive_burn_id(ETH_MAINNET_CHAIN_ID, &lez_owner, &recipient, amount, 1, 500);

    // If an attester is removed, it cannot authorize withdrawals
    locker.attester_authority = [0xaa; 20]; // simulate stale / compromised removed key
    assert_eq!(
        locker.unlock_eth(burn_id, amount, lez_owner, recipient, 1, 500),
        Err("UnauthorizedAttester")
    );

    // Active attester2 succeeds
    locker.attester_authority = attester2;
    assert_eq!(
        locker.unlock_eth(burn_id, amount, lez_owner, recipient, 1, 500),
        Ok(())
    );
}

#[test]
fn test_authority_rotation_updates_committee_count_and_preserves_quorum() {
    let locker_addr = [0x77; 20];
    let mut locker = MockEthereumLocker::new(locker_addr);
    let attester2 = [0xbb; 20];
    let attester3 = [0xcc; 20];

    // Add attester2 and attester3
    locker
        .propose_add_attester(attester2, 1000)
        .expect("add attester2");
    locker
        .execute_add_attester(1000 + GOVERNANCE_TIMELOCK_DELAY)
        .expect("exec add attester2");

    locker
        .propose_add_attester(attester3, 200_000)
        .expect("add attester3");
    locker
        .execute_add_attester(200_000 + GOVERNANCE_TIMELOCK_DELAY)
        .expect("exec add attester3");

    assert_eq!(locker.attester_count, 3);

    // Set quorum to 3
    locker.set_quorum(3).expect("set quorum 3");
    assert_eq!(locker.required_quorum, 3);

    // Rotate authority to attester2 (who was already in the committee)
    locker
        .propose_attester_authority(attester2, 400_000)
        .expect("propose authority");

    // Authority rotation attempting to drop active committee count below quorum must strictly revert!
    let err = locker
        .execute_attester_authority(400_000 + AUTHORITY_CHANGE_DELAY)
        .unwrap_err();
    assert_eq!(
        err, "InvalidQuorum",
        "Authority rotation must revert if count drops below quorum"
    );

    // Guardian can cancel the pending authority rotation
    let guardian = locker.guardian;
    locker
        .cancel_pending_governance(guardian, 6)
        .expect("guardian cancel authority rotation");
    assert_eq!(locker.pending_attester_authority, None);

    // Correct governance path: First reduce quorum to 2 via propose/execute quorum with 2-day timelock
    locker.propose_quorum(2, 500_000).expect("propose quorum 2");
    locker
        .execute_quorum(500_000 + GOVERNANCE_TIMELOCK_DELAY)
        .expect("exec quorum 2");
    assert_eq!(locker.required_quorum, 2);

    // Now re-propose and execute authority rotation to attester2
    locker
        .propose_attester_authority(attester2, 700_000)
        .expect("propose authority");
    locker
        .execute_attester_authority(700_000 + AUTHORITY_CHANGE_DELAY)
        .expect("exec authority");

    // Old authority [0xaa; 20] removed, attester2 was already in committee
    // Active attesters: attester2, attester3 (count = 2)
    assert_eq!(
        locker.attester_count, 2,
        "attester count must accurately update to 2"
    );
    // Quorum was 2 and remains 2 (never silently downgraded)
    assert_eq!(locker.required_quorum, 2, "required quorum remains 2");
}

#[test]
fn test_rolling_limit_dos_cleanup_pruning() {
    let locker_addr = [0x77; 20];
    let mut locker = MockEthereumLocker::new(locker_addr);
    locker.daily_withdrawal_limit_eth = 10_000_000_000_000_000_000; // 10 ETH
    locker.deposit_eth(50_000_000_000_000_000_000); // 50 ETH

    let lez_owner = [0x55; 32];
    let recipient = [0x88; 20];
    let small_amount = 200_000_000_000_000_000; // 0.2 ETH

    // Perform 40 small withdrawals at t = 1000
    for i in 1..=40 {
        let burn_id = derive_burn_id(
            ETH_MAINNET_CHAIN_ID,
            &lez_owner,
            &recipient,
            small_amount,
            i,
            500 + i,
        );
        locker
            .unlock_eth_with_time(
                burn_id,
                small_amount,
                lez_owner,
                recipient,
                i,
                500 + i,
                1000,
            )
            .expect("small unlock");
    }

    assert_eq!(locker.daily_withdrawn_eth, 8_000_000_000_000_000_000); // 8 ETH

    // Warp 25 hours later (t = 1000 + 90_000): all 40 withdrawals are expired
    let now = 1000 + 90_000;

    // A large withdrawal of 9 ETH (under 10 ETH limit) must succeed
    let large_amount = 9_000_000_000_000_000_000; // 9 ETH
    let large_burn_id = derive_burn_id(
        ETH_MAINNET_CHAIN_ID,
        &lez_owner,
        &recipient,
        large_amount,
        999,
        60_000,
    );
    assert_eq!(
        locker.unlock_eth_with_time(
            large_burn_id,
            large_amount,
            lez_owner,
            recipient,
            999,
            60_000,
            now,
        ),
        Ok(())
    );
    assert_eq!(locker.daily_withdrawn_eth, large_amount);
}

#[test]
fn test_two_way_bridge_cross_instance_burn_domain_separation() {
    let instance_a = [0xAA; 32];
    let instance_b = [0xBB; 32];
    let lez_owner = [0x11; 32];
    let recipient = [0x22; 20];
    let token = [0x33; 20];
    let amount = 1_000_000_000_000_000_000u128;
    let nonce = 1u64;
    let slot = 5000u64;

    // 1. Native ETH burn ID V2 with instance binding
    let burn_id_a = derive_burn_id_v2(
        ETH_MAINNET_CHAIN_ID,
        &instance_a,
        &lez_owner,
        &recipient,
        amount,
        nonce,
        slot,
    );
    let burn_id_b = derive_burn_id_v2(
        ETH_MAINNET_CHAIN_ID,
        &instance_b,
        &lez_owner,
        &recipient,
        amount,
        nonce,
        slot,
    );

    assert_ne!(
        burn_id_a, burn_id_b,
        "Identical burn parameters for different LEZ instances MUST yield distinct burn IDs"
    );

    // 2. ERC-20 burn ID V2 with instance binding
    let erc20_burn_id_a = derive_burn_erc20_id_v2(
        ETH_MAINNET_CHAIN_ID,
        &instance_a,
        &token,
        &lez_owner,
        &recipient,
        amount,
        nonce,
        slot,
    );
    let erc20_burn_id_b = derive_burn_erc20_id_v2(
        ETH_MAINNET_CHAIN_ID,
        &instance_b,
        &token,
        &lez_owner,
        &recipient,
        amount,
        nonce,
        slot,
    );

    assert_ne!(
        erc20_burn_id_a, erc20_burn_id_b,
        "Identical ERC-20 burn parameters for different LEZ instances MUST yield distinct burn IDs"
    );
}
