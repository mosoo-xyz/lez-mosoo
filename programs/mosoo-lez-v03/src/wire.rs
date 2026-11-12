//! Borsh wire types mapping deterministically into `mosoo-core` types.

use alloy_primitives::{Address, Bytes, B256};
use borsh::{BorshDeserialize, BorshSerialize};
use mosoo_core::{
    crypto::ComplementKeyWitness,
    inclusion::{ProofTarget, StateProof},
    types::{
        BeaconBlockHeader, ExecutionPayloadHeader, LightClientUpdate, NetworkConfig, Predicate,
        PrivacyMode, SyncAggregate, SyncCommittee,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireBeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl From<&WireBeaconHeader> for BeaconBlockHeader {
    fn from(h: &WireBeaconHeader) -> Self {
        Self {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root,
            state_root: h.state_root,
            body_root: h.body_root,
        }
    }
}

impl From<&BeaconBlockHeader> for WireBeaconHeader {
    fn from(h: &BeaconBlockHeader) -> Self {
        Self {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root,
            state_root: h.state_root,
            body_root: h.body_root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes48(pub [u8; 48]);

impl BorshSerialize for Bytes48 {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl BorshDeserialize for Bytes48 {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut buf = [0u8; 48];
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes96(pub [u8; 96]);

impl BorshSerialize for Bytes96 {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl BorshDeserialize for Bytes96 {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut buf = [0u8; 96];
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireSyncCommittee {
    pub pubkeys: Vec<Bytes48>,
    pub aggregate_pubkey: Bytes48,
}

impl From<&WireSyncCommittee> for SyncCommittee {
    fn from(c: &WireSyncCommittee) -> Self {
        Self {
            pubkeys: c.pubkeys.iter().map(|pk| pk.0.to_vec()).collect(),
            aggregate_pubkey: c.aggregate_pubkey.0.to_vec(),
        }
    }
}

impl From<&SyncCommittee> for WireSyncCommittee {
    fn from(c: &SyncCommittee) -> Self {
        Self {
            pubkeys: c
                .pubkeys
                .iter()
                .map(|pk| Bytes48(pk.as_slice().try_into().expect("48-byte BLS pubkey")))
                .collect(),
            aggregate_pubkey: Bytes48(
                c.aggregate_pubkey
                    .as_slice()
                    .try_into()
                    .expect("48-byte BLS aggregate pubkey"),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireSyncAggregate {
    pub sync_committee_bits: Vec<u8>,
    pub sync_committee_signature: Vec<u8>,
}

impl From<&WireSyncAggregate> for SyncAggregate {
    fn from(a: &WireSyncAggregate) -> Self {
        Self {
            sync_committee_bits: a.sync_committee_bits.clone(),
            sync_committee_signature: a.sync_committee_signature.clone(),
        }
    }
}

impl From<&SyncAggregate> for WireSyncAggregate {
    fn from(a: &SyncAggregate) -> Self {
        Self {
            sync_committee_bits: a.sync_committee_bits.clone(),
            sync_committee_signature: a.sync_committee_signature.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireExecutionPayloadHeader {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: Vec<u8>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions_root: [u8; 32],
    pub withdrawals_root: Option<[u8; 32]>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
}

impl From<&WireExecutionPayloadHeader> for ExecutionPayloadHeader {
    fn from(p: &WireExecutionPayloadHeader) -> Self {
        Self {
            parent_hash: p.parent_hash,
            fee_recipient: p.fee_recipient,
            state_root: p.state_root,
            receipts_root: p.receipts_root,
            logs_bloom: p.logs_bloom.clone(),
            prev_randao: p.prev_randao,
            block_number: p.block_number,
            gas_limit: p.gas_limit,
            gas_used: p.gas_used,
            timestamp: p.timestamp,
            extra_data: p.extra_data.clone(),
            base_fee_per_gas: p.base_fee_per_gas,
            block_hash: p.block_hash,
            transactions_root: p.transactions_root,
            withdrawals_root: p.withdrawals_root,
            blob_gas_used: p.blob_gas_used,
            excess_blob_gas: p.excess_blob_gas,
        }
    }
}

impl From<&ExecutionPayloadHeader> for WireExecutionPayloadHeader {
    fn from(p: &ExecutionPayloadHeader) -> Self {
        Self {
            parent_hash: p.parent_hash,
            fee_recipient: p.fee_recipient,
            state_root: p.state_root,
            receipts_root: p.receipts_root,
            logs_bloom: p.logs_bloom.clone(),
            prev_randao: p.prev_randao,
            block_number: p.block_number,
            gas_limit: p.gas_limit,
            gas_used: p.gas_used,
            timestamp: p.timestamp,
            extra_data: p.extra_data.clone(),
            base_fee_per_gas: p.base_fee_per_gas,
            block_hash: p.block_hash,
            transactions_root: p.transactions_root,
            withdrawals_root: p.withdrawals_root,
            blob_gas_used: p.blob_gas_used,
            excess_blob_gas: p.excess_blob_gas,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireUpdate {
    pub attested_header: WireBeaconHeader,
    pub next_sync_committee: Option<WireSyncCommittee>,
    pub next_sync_committee_branch: Option<Vec<[u8; 32]>>,
    pub finalized_header: WireBeaconHeader,
    pub finality_branch: Vec<[u8; 32]>,
    pub execution_payload_header: Option<WireExecutionPayloadHeader>,
    pub execution_branch: Option<Vec<[u8; 32]>>,
    pub execution_rlp: Option<Vec<u8>>,
    pub sync_aggregate: WireSyncAggregate,
    pub signature_slot: u64,
}

impl From<&WireUpdate> for LightClientUpdate {
    fn from(u: &WireUpdate) -> Self {
        Self {
            attested_header: (&u.attested_header).into(),
            next_sync_committee: u.next_sync_committee.as_ref().map(Into::into),
            next_sync_committee_branch: u.next_sync_committee_branch.clone(),
            finalized_header: (&u.finalized_header).into(),
            finality_branch: u.finality_branch.clone(),
            execution_payload_header: u.execution_payload_header.as_ref().map(Into::into),
            execution_branch: u.execution_branch.clone(),
            execution_rlp: u.execution_rlp.clone(),
            sync_aggregate: (&u.sync_aggregate).into(),
            signature_slot: u.signature_slot,
        }
    }
}

impl From<&LightClientUpdate> for WireUpdate {
    fn from(u: &LightClientUpdate) -> Self {
        Self {
            attested_header: (&u.attested_header).into(),
            next_sync_committee: u.next_sync_committee.as_ref().map(Into::into),
            next_sync_committee_branch: u.next_sync_committee_branch.clone(),
            finalized_header: (&u.finalized_header).into(),
            finality_branch: u.finality_branch.clone(),
            execution_payload_header: u.execution_payload_header.as_ref().map(Into::into),
            execution_branch: u.execution_branch.clone(),
            execution_rlp: u.execution_rlp.clone(),
            sync_aggregate: (&u.sync_aggregate).into(),
            signature_slot: u.signature_slot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireKeyWitness {
    pub agg_pk_uncompressed: Bytes96,
    pub non_signer_pks_uncompressed: Vec<Bytes96>,
}

impl From<&WireKeyWitness> for ComplementKeyWitness {
    fn from(w: &WireKeyWitness) -> Self {
        Self {
            agg_pk_uncompressed: w.agg_pk_uncompressed.0.to_vec(),
            non_signer_pks_uncompressed: w
                .non_signer_pks_uncompressed
                .iter()
                .map(|p| p.0.to_vec())
                .collect(),
        }
    }
}

impl From<&ComplementKeyWitness> for WireKeyWitness {
    fn from(w: &ComplementKeyWitness) -> Self {
        Self {
            agg_pk_uncompressed: Bytes96(
                w.agg_pk_uncompressed
                    .as_slice()
                    .try_into()
                    .expect("96-byte uncompressed G1 point"),
            ),
            non_signer_pks_uncompressed: w
                .non_signer_pks_uncompressed
                .iter()
                .map(|p| {
                    Bytes96(
                        p.as_slice()
                            .try_into()
                            .expect("96-byte uncompressed G1 point"),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireNetworkConfig {
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    pub trusted_checkpoint_root: Option<[u8; 32]>,
    pub altair_fork_version: [u8; 4],
    pub bellatrix_fork_version: [u8; 4],
    pub capella_fork_version: [u8; 4],
    pub deneb_fork_version: [u8; 4],
    pub electra_fork_version: [u8; 4],
    pub fulu_fork_version: [u8; 4],
    pub gloas_fork_version: [u8; 4],
}

impl From<&WireNetworkConfig> for NetworkConfig {
    fn from(c: &WireNetworkConfig) -> Self {
        Self {
            chain_id: c.chain_id,
            genesis_validators_root: c.genesis_validators_root,
            trusted_checkpoint_root: c.trusted_checkpoint_root,
            altair_fork_version: c.altair_fork_version,
            bellatrix_fork_version: c.bellatrix_fork_version,
            capella_fork_version: c.capella_fork_version,
            deneb_fork_version: c.deneb_fork_version,
            electra_fork_version: c.electra_fork_version,
            fulu_fork_version: c.fulu_fork_version,
            gloas_fork_version: c.gloas_fork_version,
        }
    }
}

impl From<&NetworkConfig> for WireNetworkConfig {
    fn from(c: &NetworkConfig) -> Self {
        Self {
            chain_id: c.chain_id,
            genesis_validators_root: c.genesis_validators_root,
            trusted_checkpoint_root: c.trusted_checkpoint_root,
            altair_fork_version: c.altair_fork_version,
            bellatrix_fork_version: c.bellatrix_fork_version,
            capella_fork_version: c.capella_fork_version,
            deneb_fork_version: c.deneb_fork_version,
            electra_fork_version: c.electra_fork_version,
            fulu_fork_version: c.fulu_fork_version,
            gloas_fork_version: c.gloas_fork_version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum WireProofTarget {
    AccountBalance {
        address: [u8; 20],
    },
    StorageSlot {
        contract: [u8; 20],
        slot: [u8; 32],
    },
    ReceiptLog {
        tx_index: u64,
        log_index: u64,
        emitter: [u8; 20],
        topic0: [u8; 32],
    },
    Erc20Transfer {
        tx_index: u64,
        log_index: u64,
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
    NativeEthDeposit {
        tx_index: u64,
        log_index: u64,
        deposit_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
    Erc20Deposit {
        tx_index: u64,
        log_index: u64,
        deposit_contract: [u8; 20],
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
    ShieldedCommitmentDeposit {
        tx_index: u64,
        log_index: u64,
        deposit_contract: [u8; 20],
        token_contract: [u8; 20],
        commitment: [u8; 32],
    },
}

impl From<&WireProofTarget> for ProofTarget {
    fn from(t: &WireProofTarget) -> Self {
        match t {
            WireProofTarget::AccountBalance { address } => ProofTarget::AccountBalance {
                address: Address::from(*address),
            },
            WireProofTarget::StorageSlot { contract, slot } => ProofTarget::StorageSlot {
                contract: Address::from(*contract),
                slot: B256::from(*slot),
            },
            WireProofTarget::ReceiptLog {
                tx_index,
                log_index,
                emitter,
                topic0,
            } => ProofTarget::ReceiptLog {
                tx_index: *tx_index,
                log_index: *log_index as usize,
                emitter: Address::from(*emitter),
                topic0: B256::from(*topic0),
            },
            WireProofTarget::Erc20Transfer {
                tx_index,
                log_index,
                token_contract,
                sender,
                recipient,
            } => ProofTarget::Erc20Transfer {
                tx_index: *tx_index,
                log_index: *log_index as usize,
                token_contract: Address::from(*token_contract),
                sender: Address::from(*sender),
                recipient: *recipient,
            },
            WireProofTarget::NativeEthDeposit {
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => ProofTarget::NativeEthDeposit {
                tx_index: *tx_index,
                log_index: *log_index as usize,
                deposit_contract: Address::from(*deposit_contract),
                sender: Address::from(*sender),
                recipient: *recipient,
            },
            WireProofTarget::Erc20Deposit {
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            } => ProofTarget::Erc20Deposit {
                tx_index: *tx_index,
                log_index: *log_index as usize,
                deposit_contract: Address::from(*deposit_contract),
                token_contract: Address::from(*token_contract),
                sender: Address::from(*sender),
                recipient: *recipient,
            },
            WireProofTarget::ShieldedCommitmentDeposit {
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                commitment,
            } => ProofTarget::ShieldedCommitmentDeposit {
                tx_index: *tx_index,
                log_index: *log_index as usize,
                deposit_contract: Address::from(*deposit_contract),
                token_contract: Address::from(*token_contract),
                commitment: B256::from(*commitment),
            },
        }
    }
}

impl From<&ProofTarget> for WireProofTarget {
    fn from(t: &ProofTarget) -> Self {
        match t {
            ProofTarget::AccountBalance { address } => Self::AccountBalance {
                address: (*address).into(),
            },
            ProofTarget::StorageSlot { contract, slot } => Self::StorageSlot {
                contract: (*contract).into(),
                slot: (*slot).into(),
            },
            ProofTarget::ReceiptLog {
                tx_index,
                log_index,
                emitter,
                topic0,
            } => Self::ReceiptLog {
                tx_index: *tx_index,
                log_index: *log_index as u64,
                emitter: (*emitter).into(),
                topic0: (*topic0).into(),
            },
            ProofTarget::Erc20Transfer {
                tx_index,
                log_index,
                token_contract,
                sender,
                recipient,
            } => Self::Erc20Transfer {
                tx_index: *tx_index,
                log_index: *log_index as u64,
                token_contract: (*token_contract).into(),
                sender: (*sender).into(),
                recipient: *recipient,
            },
            ProofTarget::NativeEthDeposit {
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => Self::NativeEthDeposit {
                tx_index: *tx_index,
                log_index: *log_index as u64,
                deposit_contract: (*deposit_contract).into(),
                sender: (*sender).into(),
                recipient: *recipient,
            },
            ProofTarget::Erc20Deposit {
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            } => Self::Erc20Deposit {
                tx_index: *tx_index,
                log_index: *log_index as u64,
                deposit_contract: (*deposit_contract).into(),
                token_contract: (*token_contract).into(),
                sender: (*sender).into(),
                recipient: *recipient,
            },
            ProofTarget::ShieldedCommitmentDeposit {
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                commitment,
            } => Self::ShieldedCommitmentDeposit {
                tx_index: *tx_index,
                log_index: *log_index as u64,
                deposit_contract: (*deposit_contract).into(),
                token_contract: (*token_contract).into(),
                commitment: (*commitment).into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WireStateProof {
    pub target: WireProofTarget,
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Option<Vec<Vec<u8>>>,
    pub receipt_proof: Option<Vec<Vec<u8>>>,
    pub account_value: Option<Vec<u8>>,
    pub storage_value: Option<Vec<u8>>,
    pub receipt_value: Option<Vec<u8>>,
}

impl From<&WireStateProof> for StateProof {
    fn from(p: &WireStateProof) -> Self {
        Self {
            target: (&p.target).into(),
            account_proof: p
                .account_proof
                .iter()
                .map(|n| Bytes::copy_from_slice(n))
                .collect(),
            storage_proof: p
                .storage_proof
                .as_ref()
                .map(|v| v.iter().map(|n| Bytes::copy_from_slice(n)).collect()),
            receipt_proof: p
                .receipt_proof
                .as_ref()
                .map(|v| v.iter().map(|n| Bytes::copy_from_slice(n)).collect()),
            account_value: p.account_value.clone(),
            storage_value: p.storage_value.clone(),
            receipt_value: p.receipt_value.clone(),
        }
    }
}

impl From<&StateProof> for WireStateProof {
    fn from(p: &StateProof) -> Self {
        Self {
            target: (&p.target).into(),
            account_proof: p.account_proof.iter().map(|b| b.to_vec()).collect(),
            storage_proof: p
                .storage_proof
                .as_ref()
                .map(|v| v.iter().map(|b| b.to_vec()).collect()),
            receipt_proof: p
                .receipt_proof
                .as_ref()
                .map(|v| v.iter().map(|b| b.to_vec()).collect()),
            account_value: p.account_value.clone(),
            storage_value: p.storage_value.clone(),
            receipt_value: p.receipt_value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum WirePredicate {
    Equal { expected: [u8; 32] },
    AtLeast { min: [u8; 32] },
    LessThan { max: [u8; 32] },
    All(Vec<WirePredicate>),
    Any(Vec<WirePredicate>),
}

impl From<&WirePredicate> for Predicate {
    fn from(p: &WirePredicate) -> Self {
        match p {
            WirePredicate::Equal { expected } => Predicate::Equal {
                expected: *expected,
            },
            WirePredicate::AtLeast { min } => Predicate::AtLeast { min: *min },
            WirePredicate::LessThan { max } => Predicate::LessThan { max: *max },
            WirePredicate::All(items) => Predicate::All(items.iter().map(Into::into).collect()),
            WirePredicate::Any(items) => Predicate::Any(items.iter().map(Into::into).collect()),
        }
    }
}

impl From<&Predicate> for WirePredicate {
    fn from(p: &Predicate) -> Self {
        match p {
            Predicate::Equal { expected } => Self::Equal {
                expected: *expected,
            },
            Predicate::AtLeast { min } => Self::AtLeast { min: *min },
            Predicate::LessThan { max } => Self::LessThan { max: *max },
            Predicate::All(items) => Self::All(items.iter().map(Into::into).collect()),
            Predicate::Any(items) => Self::Any(items.iter().map(Into::into).collect()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum WirePrivacyMode {
    Public,
    AddressPrivate,
    Confidential,
}

impl From<&WirePrivacyMode> for PrivacyMode {
    fn from(m: &WirePrivacyMode) -> Self {
        match m {
            WirePrivacyMode::Public => PrivacyMode::Public,
            WirePrivacyMode::AddressPrivate => PrivacyMode::AddressPrivate,
            WirePrivacyMode::Confidential => PrivacyMode::Confidential,
        }
    }
}
