//! Core account and message types shared between the guest program and the host.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};

pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_SEPOLIA_CHAIN_ID: u64 = 11_155_111;
pub const ETH_HOLESKY_CHAIN_ID: u64 = 17_000;

/// Canonical Sepolia MosooLocker contract address (deployed at block 11989329, tx 0x1b49...b28b)
pub const CANONICAL_SEPOLIA_MOSOO_LOCKER: [u8; 20] = [
    0x74, 0x62, 0x5d, 0x14, 0x6b, 0x8d, 0x94, 0x13, 0xf3, 0xc3, 0x97, 0x6b, 0x32, 0x3d, 0x94, 0xa7,
    0x39, 0xbe, 0x78, 0x56,
];

/// Returns true if the provided chain ID is a supported Ethereum network (Mainnet, Sepolia, Holesky).
/// Light-client consensus tracking and inclusion proof verification are fully supported across all 3 chains.
pub const fn is_supported_chain_id(chain_id: u64) -> bool {
    chain_id == ETH_MAINNET_CHAIN_ID
        || chain_id == ETH_SEPOLIA_CHAIN_ID
        || chain_id == ETH_HOLESKY_CHAIN_ID
}

/// Returns the canonical deployed bridge locker contract address for a given chain ID, if deployed.
///
/// Note: Core Ethereum consensus and state proof verification (`AttestState`, `HeaderRecord`, `InstanceAccount`)
/// support Mainnet, Sepolia, and Holesky via `is_supported_chain_id(chain_id)`.
/// For bridge escrow locking (`MosooLocker.sol`), Sepolia has an authentic deployed testnet contract
/// ([`CANONICAL_SEPOLIA_MOSOO_LOCKER`]). Mainnet and Holesky bridge contracts are pending production
/// deployment, returning `None` until an authenticated address is explicitly registered via [`TrustedBridgeConfig`].
pub const fn get_canonical_trusted_locker(chain_id: u64) -> Option<[u8; 20]> {
    match chain_id {
        ETH_SEPOLIA_CHAIN_ID => Some(CANONICAL_SEPOLIA_MOSOO_LOCKER),
        _ => None,
    }
}

/// Authenticated program-owned configuration specifying trusted locker contracts and allowed tokens per chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedBridgeConfig {
    /// Optional administrative authority key (32 bytes) authorized to update lockers or token allowlists.
    pub admin_authority: Option<[u8; 32]>,
    /// Trusted locker vault contracts per chain ID
    pub trusted_lockers: HashMap<u64, [u8; 20]>,
    /// Strict token allowlist per chain ID (default-deny: tokens must be explicitly allowlisted)
    pub allowed_tokens: HashMap<u64, HashSet<[u8; 20]>>,
}

impl Default for TrustedBridgeConfig {
    fn default() -> Self {
        Self::canonical()
    }
}

impl TrustedBridgeConfig {
    /// Initialize with canonical production and testnet locker contracts and verified token allowlists.
    pub fn canonical() -> Self {
        let mut trusted_lockers = HashMap::new();
        // Register authentic deployed Sepolia testnet locker
        trusted_lockers.insert(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_MOSOO_LOCKER);

        let mut allowed_tokens = HashMap::new();
        let mut sepolia_tokens = HashSet::new();
        // Canonical Sepolia testnet tokens:
        // MockUSDC (Circle Sepolia testnet: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238)
        sepolia_tokens.insert([
            0x1c, 0x7d, 0x4b, 0x19, 0x6c, 0xb0, 0xc7, 0xb0, 0x1d, 0x74, 0x3f, 0xbc, 0x61, 0x16,
            0xa9, 0x02, 0x37, 0x9c, 0x72, 0x38,
        ]);
        // MockUSDT (Sepolia testnet: 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06)
        sepolia_tokens.insert([
            0x71, 0x69, 0xd3, 0x88, 0x20, 0xdf, 0xd1, 0x17, 0xc3, 0xfa, 0x1f, 0x22, 0xa6, 0x97,
            0xdb, 0xa5, 0x8d, 0x90, 0xba, 0x06,
        ]);
        allowed_tokens.insert(ETH_SEPOLIA_CHAIN_ID, sepolia_tokens);

        Self {
            admin_authority: None,
            trusted_lockers,
            allowed_tokens,
        }
    }

    /// Configures or updates the administrative authority key.
    pub fn set_admin_authority(&mut self, admin: [u8; 32]) {
        self.admin_authority = Some(admin);
    }

    /// Registers or updates the trusted locker contract for a given chain ID.
    /// Strictly rejects the zero address.
    pub fn register_trusted_locker(&mut self, chain_id: u64, locker: [u8; 20]) -> bool {
        if locker == [0u8; 20] {
            return false;
        }
        self.trusted_lockers.insert(chain_id, locker);
        true
    }

    /// Registers or updates the trusted locker contract if caller matches the authorized administrative authority.
    /// Strictly fail-closed: If `admin_authority` is not configured (`None`), all mutations are strictly rejected.
    pub fn register_trusted_locker_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        locker: [u8; 20],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false; // Fail-closed: unconfigured admin authority strictly rejects registration
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_locker(chain_id, locker)
    }

    /// Returns the registered trusted locker contract for a given chain ID, if configured.
    pub fn get_trusted_locker(&self, chain_id: u64) -> Option<[u8; 20]> {
        self.trusted_lockers.get(&chain_id).copied()
    }

    /// Returns true if candidate address is non-zero and exactly matches the registered trusted locker.
    pub fn is_trusted_locker(&self, chain_id: u64, candidate: &[u8; 20]) -> bool {
        if *candidate == [0u8; 20] {
            return false;
        }
        self.trusted_lockers.get(&chain_id) == Some(candidate)
    }

    /// Whitelists an ERC-20 token contract for a given chain ID.
    pub fn allow_token(&mut self, chain_id: u64, token: [u8; 20]) -> bool {
        if token == [0u8; 20] {
            return false;
        }
        self.allowed_tokens
            .entry(chain_id)
            .or_default()
            .insert(token);
        true
    }

    /// Whitelists an ERC-20 token contract if caller matches the authorized administrative authority.
    /// Strictly fail-closed: If `admin_authority` is not configured (`None`), all mutations are strictly rejected.
    pub fn allow_token_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        token: [u8; 20],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false; // Fail-closed: unconfigured admin authority strictly rejects allowlist changes
        };
        if *caller != expected_admin {
            return false;
        }
        self.allow_token(chain_id, token)
    }

    /// Checks if a token is permitted. Strictly default-deny:
    /// Returns true ONLY if an allowlist is configured for this chain and the token is explicitly present.
    pub fn is_token_allowed(&self, chain_id: u64, token: &[u8; 20]) -> bool {
        if *token == [0u8; 20] {
            return false;
        }
        match self.allowed_tokens.get(&chain_id) {
            None => false, // STRICT DEFAULT-DENY: unconfigured chains reject all tokens!
            Some(set) => set.contains(token),
        }
    }
}

/// A single beacon block header (Ethereum Altair / Bellatrix+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

/// The 512-member BLS12-381 sync committee used by Ethereum Altair consensus.
///
/// Each validator's compressed G1 public key is 48 bytes.
/// Stored as Vec<u8> per pubkey to work with serde without extra dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommittee {
    /// 512 compressed BLS12-381 G1 pubkeys, each 48 bytes.
    pub pubkeys: Vec<Vec<u8>>,
    /// Aggregate pubkey: sum of all 512 keys, 48 bytes.
    pub aggregate_pubkey: Vec<u8>,
}

impl SyncCommittee {
    /// Return pubkey `i` as a fixed 48-byte array, or error if length wrong.
    pub fn pubkey_bytes(&self, i: usize) -> Option<[u8; 48]> {
        let pk = self.pubkeys.get(i)?;
        if pk.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(pk);
        Some(arr)
    }

    /// Return the aggregate pubkey as a fixed 48-byte array.
    pub fn agg_pubkey_bytes(&self) -> Option<[u8; 48]> {
        if self.aggregate_pubkey.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&self.aggregate_pubkey);
        Some(arr)
    }
}

/// The sync-committee aggregate signature attached to a beacon block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAggregate {
    /// 512-bit participation bitvector packed into 64 bytes.
    pub sync_committee_bits: Vec<u8>,
    /// BLS12-381 G2 aggregate signature, 96 bytes compressed.
    pub sync_committee_signature: Vec<u8>,
}

impl SyncAggregate {
    /// Return the signature as a fixed 96-byte array, or None if length wrong.
    pub fn signature_bytes(&self) -> Option<[u8; 96]> {
        if self.sync_committee_signature.len() != 96 {
            return None;
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&self.sync_committee_signature);
        Some(arr)
    }
}

/// Canonical Mosoo program ID on Logos Execution Zone (LEZ)
pub const MOSOO_PROGRAM_ID: [u8; 32] = [
    0x01, 0xab, 0x35, 0xfd, 0xa4, 0x34, 0xbd, 0xfe, 0x7a, 0xf6, 0x01, 0xea, 0xbc, 0x14, 0x99, 0x2b,
    0x9c, 0xa8, 0x07, 0xbc, 0x4d, 0xdf, 0xec, 0x46, 0xc8, 0x96, 0xd8, 0x1d, 0xc4, 0x96, 0x1e, 0x1c,
];

/// Execution payload header for Bellatrix/Capella/Deneb/Electra consensus specs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPayloadHeader {
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
    /// Deneb / Electra / Gloas additions (17 fields total, 32 leaves in SSZ container).
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
}

/// A full Ethereum light-client update as returned by the beacon API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientUpdate {
    pub attested_header: BeaconBlockHeader,
    pub next_sync_committee: Option<SyncCommittee>,
    /// Merkle branch proving `next_sync_committee` in the attested state.
    pub next_sync_committee_branch: Option<Vec<[u8; 32]>>,
    pub finalized_header: BeaconBlockHeader,
    /// Merkle branch proving finalized_header in the attested state.
    pub finality_branch: Vec<[u8; 32]>,
    /// Execution payload header for finalized_header.
    pub execution_payload_header: Option<ExecutionPayloadHeader>,
    /// Merkle branch proving execution_payload_header in finalized_header.body_root (gindex 25).
    pub execution_branch: Option<Vec<[u8; 32]>>,
    /// RLP-encoded execution block header (mandatory for Gloas ePBS to derive state_root and receipts_root from block_hash).
    #[serde(default)]
    pub execution_rlp: Option<Vec<u8>>,
    pub sync_aggregate: SyncAggregate,
    /// Slot at which the sync_aggregate was created (for domain computation).
    pub signature_slot: u64,
}

/// Ethereum Altair sync committee period constant (256 epochs * 32 slots = 8,192 slots, ~27.3 hours).
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8192;

/// Compute the sync committee period for a given slot.
#[inline]
pub fn compute_sync_committee_period(slot: u64) -> u64 {
    slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
}

/// Explicit consensus network configuration parameters.
/// Allows the same uncompiled program binary to track any Ethereum-consensus network
/// (including devnets and L2s with custom genesis validators root and fork schedules)
/// per RFP-021 Functionality #14.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    #[serde(default)]
    pub altair_fork_version: [u8; 4],
    #[serde(default)]
    pub bellatrix_fork_version: [u8; 4],
    #[serde(default)]
    pub capella_fork_version: [u8; 4],
    #[serde(default)]
    pub deneb_fork_version: [u8; 4],
    #[serde(default)]
    pub electra_fork_version: [u8; 4],
    #[serde(default)]
    pub fulu_fork_version: [u8; 4],
    #[serde(default)]
    pub gloas_fork_version: [u8; 4],
}

/// **Instance Account** — light client tracker instance on LEZ.
///
/// PDA seed: `["mosoo_instance", chain_id.to_le_bytes(), instance_id]`
/// Multiple independent instances can coexist on the same chain (RFP-021 Functionality #15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceAccount {
    /// Unique instance identifier (enables multiple independent instances per chain).
    #[serde(default)]
    pub instance_id: [u8; 32],
    /// EIP-155 chain ID (1 = mainnet, 11155111 = Sepolia …).
    pub chain_id: u64,
    /// SHA-256 of the last accepted finalized BeaconBlockHeader (SSZ-encoded).
    pub current_header_hash: [u8; 32],
    /// Beacon state root of the last accepted finalized BeaconBlockHeader (for historical block roots anchor).
    pub current_state_root: [u8; 32],
    /// Slot number of the last accepted finalized header.
    pub current_slot: u64,
    /// Active sync committee (the one that signed the last update).
    pub current_sync_committee: SyncCommittee,
    /// Next-period committee cached for handoff (may be None between handoffs).
    pub next_sync_committee: Option<SyncCommittee>,
    /// Bootstrap slot — the weak-subjectivity trust anchor slot.
    pub bootstrap_slot: u64,
    /// Immutable bootstrap checkpoint beacon block root.
    #[serde(default)]
    pub bootstrap_header_hash: [u8; 32],
    /// Whether this instance has been initialized.
    pub initialized: bool,
    /// Execution block hash of the last accepted finalized header.
    #[serde(default)]
    pub current_execution_block_hash: [u8; 32],
    /// Execution state root of the last accepted finalized header.
    #[serde(default)]
    pub current_execution_state_root: [u8; 32],
    /// Execution receipts root of the last accepted finalized header.
    #[serde(default)]
    pub current_receipts_root: [u8; 32],
    /// Optional network configuration for custom or non-whitelisted consensus networks.
    #[serde(default)]
    pub network_config: Option<NetworkConfig>,
}

impl InstanceAccount {
    /// Returns true if the instance has stalled past Ethereum's weak-subjectivity window (1,728,000 slots / 54,000 epochs / ~240 days).
    pub fn is_stale(&self, network_slot: u64) -> bool {
        network_slot > self.current_slot + 1_728_000
    }

    /// Computes the deterministic 32-byte PDA address of this instance account on LEZ.
    pub fn pda_address(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"mosoo_instance");
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.instance_id);
        hasher.finalize().into()
    }

    /// Validates the internal authenticity invariants of this instance account.
    /// Strictly rejects uninitialized instances, missing bootstrap roots, or inverted slot ordering.
    pub fn validate_authenticity(&self) -> Result<(), &'static str> {
        if !self.initialized {
            return Err("Instance account is not initialized");
        }
        if self.bootstrap_slot == 0 {
            return Err("Instance account bootstrap_slot cannot be zero");
        }
        if self.bootstrap_header_hash == [0u8; 32] {
            return Err("Instance account bootstrap_header_hash cannot be zero");
        }
        if self.current_sync_committee.pubkeys.len() != 512 {
            return Err("Instance account sync committee must have exactly 512 validator keys");
        }
        if self.current_slot < self.bootstrap_slot {
            return Err("Instance account current_slot cannot be earlier than bootstrap_slot");
        }
        Ok(())
    }
}

/// Persistent storage abstraction for LEZ Program-Derived Accounts (PDAs).
pub trait AccountStore {
    fn get_account(&self, address: &[u8; 32]) -> Option<Vec<u8>>;
    fn set_account(&mut self, address: &[u8; 32], data: Vec<u8>);
    fn has_account(&self, address: &[u8; 32]) -> bool {
        self.get_account(address).is_some()
    }
}

impl AccountStore for std::collections::HashMap<[u8; 32], Vec<u8>> {
    fn get_account(&self, address: &[u8; 32]) -> Option<Vec<u8>> {
        self.get(address).cloned()
    }
    fn set_account(&mut self, address: &[u8; 32], data: Vec<u8>) {
        self.insert(*address, data);
    }
}

/// **Job Account** — tracks a pending 3-transaction BLS verification job.
///
/// BLS verification is split across 3 transactions to stay under the LEZ
/// ~10 M gas cap per transaction:
///
///   Tx 1 `begin`:  participation check + hash_to_G2     ≈ 5.4 M gas
///   Tx 2 `miller`: two Miller-loop pairings             ≈ 4.2 M gas
///   Tx 3 `finish`: final exponentiation + state write   ≈ 3.8 M gas
///
/// PDA seed: `["mosoo_job", instance_pubkey, nonce.to_le_bytes()]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAccount {
    /// Unique instance identifier this job belongs to.
    #[serde(default)]
    pub instance_id: [u8; 32],
    /// Which instance chain ID this job belongs to.
    pub instance_chain_id: u64,
    /// Head slot of the instance when this job began (cross-stage monotonicity check).
    pub instance_slot: u64,
    /// Current processing stage.
    pub stage: JobStage,
    /// Cryptographic digest of the incoming update payload (tamper-proofing across stages).
    pub update_digest: [u8; 32],
    /// The full update being verified (held in the job until finish).
    pub update: LightClientUpdate,
    /// Intermediate state written by `begin`, consumed by `miller`.
    pub miller_input: Option<MillerInput>,
    /// Intermediate state written by `miller`, consumed by `finish`.
    pub miller_output: Option<MillerOutput>,
    /// Sequential nonce used in PDA derivation to allow concurrent jobs.
    pub nonce: u64,
}

/// Processing stages for a verification job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStage {
    Begin,
    Miller,
    Finish,
    Done,
}

/// Data produced by the `begin` instruction and consumed by `miller`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MillerInput {
    /// Compressed G1 aggregate pubkey of the participating validators (48 bytes).
    pub agg_pubkey_compressed: Vec<u8>,
    /// G2 point: hash_to_curve(signing_root), 96 bytes compressed.
    pub msg_g2: Vec<u8>,
}

/// Data produced by the `miller` instruction and consumed by `finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MillerOutput {
    /// Raw Fp12 miller-loop results (1152 bytes = 2 x 576 bytes).
    pub miller_result: Vec<u8>,
}

/// **Header Record** — a finalized beacon header stored for consumer programs.
///
/// PDA seed: `["mosoo_header", chain_id.to_le_bytes(), slot.to_le_bytes()]`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderRecord {
    pub chain_id: u64,
    pub slot: u64,
    /// Beacon block root (SSZ hash-tree-root of the BeaconBlock).
    pub beacon_block_root: [u8; 32],
    /// Execution-layer block hash (from ExecutionPayloadHeader).
    pub execution_block_hash: [u8; 32],
    /// Execution-layer world-state root (EVM state root).
    pub execution_state_root: [u8; 32],
    /// Execution-layer receipts root (from ExecutionPayloadHeader).
    pub receipts_root: [u8; 32],
}

impl HeaderRecord {
    /// Computes the deterministic 32-byte PDA address of this HeaderRecord on LEZ.
    /// PDA seed: `["mosoo_header", chain_id.to_le_bytes(), slot.to_le_bytes()]`
    pub fn pda_address(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"mosoo_header");
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.slot.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Complete cryptographic proof binding a historical header's beacon block root
/// and its execution roots to the light client's authenticated `current_state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalHeaderProof {
    /// Proof branch anchoring historical beacon block root into instance.current_state_root (block_roots ring buffer)
    pub block_roots_branch: Vec<[u8; 32]>,
    /// The full historical beacon block header
    pub beacon_header: BeaconBlockHeader,
    /// Execution payload header for the historical block
    pub execution_payload_header: ExecutionPayloadHeader,
    /// SSZ branch binding execution payload header into beacon_header.body_root
    pub execution_branch: Vec<[u8; 32]>,
    /// Optional execution block RLP header (required for Gloas ePBS)
    pub execution_rlp: Option<Vec<u8>>,
}

/// Arguments to bootstrap / initialize a Mosoo instance account.
///
/// Cryptographically binds the initial 512-validator sync committee
/// to the trusted beacon block header via an SSZ Merkle branch at the fork's generalized index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeArgs {
    /// Unique instance identifier for this light client instance.
    /// Enables multiple independent instances to coexist on the same chain (RFP-021 Functionality #15).
    #[serde(default)]
    pub instance_id: [u8; 32],
    pub chain_id: u64,
    /// Beacon block header of the weak-subjectivity trusted checkpoint.
    pub bootstrap_header: BeaconBlockHeader,
    /// Weak-subjectivity trusted beacon block root anchor.
    /// In accordance with Ethereum light client specifications and Logos RFP-021,
    /// when specified, handle_initialize asserts that hash_tree_root(bootstrap_header) == trusted_checkpoint_root.
    #[serde(default)]
    pub trusted_checkpoint_root: [u8; 32],
    /// Sync committee active at the bootstrap slot (512 BLS pubkeys).
    pub current_sync_committee: SyncCommittee,
    /// SSZ Merkle branch proving `current_sync_committee` at generalized index (54 for Altair/Deneb, 86 for Electra/Fulu, 2945 for Gloas).
    pub current_sync_committee_branch: Vec<[u8; 32]>,
    /// Optional next-period committee if already known at bootstrap.
    pub initial_next_committee: Option<SyncCommittee>,
    /// SSZ Merkle branch proving `initial_next_committee` at generalized index (55 for Altair/Deneb, 87 for Electra/Fulu, 2946 for Gloas).
    /// Required if `initial_next_committee` is provided.
    pub initial_next_committee_branch: Option<Vec<[u8; 32]>>,
    /// Mandatory operator-attested trusted network head slot for enforcing weak subjectivity freshness.
    pub trusted_head_slot: u64,
    /// Optional custom consensus network configuration.
    #[serde(default)]
    pub network_config: Option<NetworkConfig>,
}

/// Helper to derive the PDA seeds for an instance account.
/// Allows multiple independent instances on the same Ethereum chain.
pub fn derive_instance_pda_seeds<'a>(
    chain_id_bytes: &'a [u8; 8],
    instance_id: &'a [u8; 32],
) -> [&'a [u8]; 3] {
    [b"mosoo_instance", chain_id_bytes, instance_id]
}

/// Legacy recovery structure.
///
/// In compliance with Logos RFP-021, light client instances are strictly immutable
/// once initialized. Stale or misconfigured instances are not mutated on-chain;
/// operators initialize a fresh instance with a new `instance_id`, and consumers migrate
/// by binding to the new instance PDA without any admin mutation backdoors.
#[deprecated(
    note = "Instances are strictly immutable once initialized per RFP-021; initialize a new instance with a unique instance_id instead"
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverInstanceArgs {
    pub instance: InstanceAccount,
    pub new_bootstrap_header: BeaconBlockHeader,
    pub new_sync_committee: SyncCommittee,
    pub new_sync_committee_branch: Vec<[u8; 32]>,
    pub initial_next_committee: Option<SyncCommittee>,
    pub initial_next_committee_branch: Option<Vec<[u8; 32]>>,
    /// Network head slot proving the existing instance has stalled past weak subjectivity (>1,728,000 slots).
    pub current_network_slot: u64,
}

/// A condition a consumer program wants to evaluate over verified Ethereum state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Predicate {
    /// Verified value equals `expected`.
    Equal { expected: [u8; 32] },
    /// Verified value (big-endian u256) ≥ `min`.
    AtLeast { min: [u8; 32] },
    /// Verified value < `max`.
    LessThan { max: [u8; 32] },
    /// All sub-predicates must hold (AND).
    All(Vec<Predicate>),
    /// At least one sub-predicate must hold (OR).
    Any(Vec<Predicate>),
}

pub const PROOF_TYPE_ACCOUNT_BALANCE: u8 = 0;
pub const PROOF_TYPE_STORAGE_SLOT: u8 = 1;
pub const PROOF_TYPE_RECEIPT_LOG: u8 = 2;
pub const PROOF_TYPE_ETH_DEPOSIT: u8 = 3;
pub const PROOF_TYPE_ERC20_TRANSFER: u8 = 4;
pub const PROOF_TYPE_ERC20_DEPOSIT: u8 = 5;

/// Canonical on-chain provenance binding of an attested Ethereum state, event, or transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatementBinding {
    /// Account balance proof
    Account { address: [u8; 20] },
    /// Storage slot proof
    Storage { contract: [u8; 20], slot: [u8; 32] },
    /// Transaction receipt event log
    ReceiptLog { emitter: [u8; 20], topic0: [u8; 32] },
    /// Native ETH deposit into a designated bridge vault contract
    NativeEthDeposit {
        execution_block_hash: [u8; 32],
        slot: u64,
        tx_index: u64,
        log_index: usize,
        deposit_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
    /// ERC-20 transfer event / vault deposit
    Erc20Transfer {
        execution_block_hash: [u8; 32],
        slot: u64,
        tx_index: u64,
        log_index: usize,
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
    /// ERC-20 deposit into a designated bridge vault contract (MosooLocker.sol)
    Erc20Deposit {
        execution_block_hash: [u8; 32],
        slot: u64,
        tx_index: u64,
        log_index: usize,
        deposit_contract: [u8; 20],
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    },
}

impl Default for StatementBinding {
    fn default() -> Self {
        StatementBinding::Account { address: [0u8; 20] }
    }
}

/// The result emitted by the attestation module for consumer programs.
///
/// `statement_id` is a collision-resistant nullifier derived deterministically
/// from `sha256(chain_id || subject_key || proof_type_tag || value || predicate)`.
/// The `subject_key` encodes the immutable on-chain identity (account address,
/// contract+storage-slot, or transfer/deposit event binding), so proving the same balance
/// at a different block slot yields the same nullifier, preventing cross-slot double-spending.
///
/// **Consumer Security:** Consuming contracts verify `attester_program_id == MOSOO_PROGRAM_ID`,
/// enforce parameter binding via `binding` & `subject_key`, and derive settlement amounts
/// strictly from `verified_value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedStatement {
    pub chain_id: u64,
    /// LEZ program ID of the authentic Mosoo attester program that emitted this statement.
    pub attester_program_id: [u8; 32],
    /// sha256(chain_id_le8 || subject_key_32 || proof_type_u8 || value_be32 || predicate_json)
    pub statement_id: [u8; 32],
    /// Whether the requested predicate held over the verified state.
    pub predicate_holds: bool,
    /// The exact 32-byte EVM value verified by the MPT inclusion proof.
    pub verified_value: [u8; 32],
    /// Canonical subject key identifying the underlying Ethereum account, storage slot, or event.
    #[serde(default)]
    pub subject_key: [u8; 32],
    /// Type of statement / verified proof target.
    #[serde(default)]
    pub proof_type_tag: u8,
    /// Canonical provenance binding preserving the on-chain origin target.
    #[serde(default)]
    pub binding: StatementBinding,
}

impl VerifiedStatement {
    /// Recomputes the canonical 32-byte statement identifier from the underlying verified state facts:
    /// `sha256("mosoo_statement_v1" || chain_id_le8 || subject_key_32 || proof_type_tag_u8 || verified_value_32)`
    pub fn derive_canonical_id(&self) -> [u8; 32] {
        crate::predicate::derive_statement_id_from_raw(
            self.chain_id,
            &self.subject_key,
            self.proof_type_tag,
            &self.verified_value,
        )
    }

    /// Decode the verified 32-byte EVM value as a U256 (big-endian).
    pub fn value_as_u256(&self) -> alloy_primitives::U256 {
        alloy_primitives::U256::from_be_bytes(self.verified_value)
    }

    /// Decode the verified 32-byte EVM value as a u128 (big-endian).
    pub fn value_as_u128(&self) -> u128 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.verified_value[16..32]);
        u128::from_be_bytes(buf)
    }

    /// Decode the verified 32-byte EVM value as a u128 (big-endian), strictly asserting that the
    /// top 16 bytes are zero to prevent silent arithmetic truncation for amounts > u128::MAX.
    pub fn value_as_u128_checked(&self) -> Result<u128, crate::error::MosooError> {
        if self.verified_value[..16] != [0u8; 16] {
            return Err(crate::error::MosooError::Internal(
                "verified statement value exceeds u128::MAX (silent truncation prevented)".into(),
            ));
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.verified_value[16..32]);
        Ok(u128::from_be_bytes(buf))
    }

    /// Decode the verified 32-byte EVM value as a u64 (big-endian), strictly asserting that the
    /// top 24 bytes are zero to prevent silent arithmetic truncation for amounts > u64::MAX (e.g. >18.44 ETH in wei).
    pub fn value_as_u64_checked(&self) -> Result<u64, crate::error::MosooError> {
        if self.verified_value[..24] != [0u8; 24] {
            return Err(crate::error::MosooError::Internal(
                "verified statement value exceeds u64::MAX (silent truncation prevented)".into(),
            ));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.verified_value[24..32]);
        Ok(u64::from_be_bytes(buf))
    }

    /// Decode the verified 32-byte EVM value as a u64 (big-endian).
    pub fn value_as_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.verified_value[24..32]);
        u64::from_be_bytes(buf)
    }
}

/// An authenticated on-chain Statement Account record on Logos Execution Zone.
/// Represents an authentic statement verified and committed on-chain by `MOSOO_PROGRAM_ID`.
/// Seed derivation: `["mosoo_statement", chain_id.to_le_bytes(), statement_id]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementAccount {
    /// Account owner program ID (must be `MOSOO_PROGRAM_ID`).
    pub owner: [u8; 32],
    /// On-chain PDA address of this statement account.
    pub pda_address: [u8; 32],
    /// The cryptographically verified statement payload.
    pub statement: VerifiedStatement,
}

impl StatementAccount {
    /// Constructs a verified StatementAccount owned by `MOSOO_PROGRAM_ID`.
    pub fn new_authentic(statement: VerifiedStatement) -> Self {
        let pda_address = derive_statement_pda(statement.chain_id, &statement.statement_id);
        Self {
            owner: MOSOO_PROGRAM_ID,
            pda_address,
            statement,
        }
    }

    /// Deserializes and validates a StatementAccount from host runtime account metadata.
    /// Strictly verifies that the host runtime authenticated owner matches `MOSOO_PROGRAM_ID`
    /// and that the account address matches the canonical PDA derivation from the statement ID.
    pub fn try_from_runtime_account(
        account: &RuntimeAccount,
    ) -> Result<Self, crate::error::MosooError> {
        if account.owner != MOSOO_PROGRAM_ID {
            return Err(crate::error::MosooError::UnauthenticatedAttester {
                expected: MOSOO_PROGRAM_ID,
                actual: account.owner,
            });
        }
        let statement: VerifiedStatement = serde_json::from_slice(&account.data).map_err(|e| {
            crate::error::MosooError::Internal(format!("malformed statement data: {e}"))
        })?;
        let expected_pda = derive_statement_pda(statement.chain_id, &statement.statement_id);
        if account.address != expected_pda {
            return Err(crate::error::MosooError::UnauthenticatedAttester {
                expected: expected_pda,
                actual: account.address,
            });
        }
        Ok(Self {
            owner: account.owner,
            pda_address: account.address,
            statement,
        })
    }
}

/// Host-provided runtime account metadata representing an on-chain LEZ account.
/// Encapsulates host sequencer CPI verification asserting authenticated account ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAccount {
    /// Owner program ID authenticated by the host sequencer/runtime.
    pub owner: [u8; 32],
    /// On-chain address of the account.
    pub address: [u8; 32],
    /// Serialized account data payload.
    pub data: Vec<u8>,
}

/// Derives the deterministic PDA address for a verified statement on LEZ.
pub fn derive_statement_pda(chain_id: u64, statement_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"mosoo_statement");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(statement_id);
    hasher.finalize().into()
}

pub use crate::verifier::{AttestStateArgs, InstructionOutput};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_bridge_config_fail_closed_authorization() {
        let mut config = TrustedBridgeConfig::canonical();
        assert_eq!(config.admin_authority, None);

        let random_caller = [0x42u8; 32];
        let test_locker = [0x55u8; 20];
        let test_token = [0x77u8; 20];

        // 1. Without admin_authority configured, authorized mutations MUST fail-closed
        assert!(!config.register_trusted_locker_authorized(&random_caller, 11155111, test_locker));
        assert!(!config.allow_token_authorized(&random_caller, 11155111, test_token));

        // 2. Configure admin authority
        let admin = [0xaau8; 32];
        config.set_admin_authority(admin);

        // Unauthorized caller is rejected
        assert!(!config.register_trusted_locker_authorized(&random_caller, 11155111, test_locker));
        assert!(!config.allow_token_authorized(&random_caller, 11155111, test_token));

        // Authorized caller succeeds
        assert!(config.register_trusted_locker_authorized(&admin, 1, test_locker));
        assert_eq!(config.get_trusted_locker(1), Some(test_locker));

        assert!(config.allow_token_authorized(&admin, 1, test_token));
        assert!(config.is_token_allowed(1, &test_token));
    }

    #[test]
    fn test_instance_account_validate_authenticity() {
        let mut instance = InstanceAccount {
            instance_id: [1u8; 32],
            chain_id: 11155111,
            current_header_hash: [2u8; 32],
            current_state_root: [3u8; 32],
            current_slot: 100,
            current_sync_committee: SyncCommittee {
                pubkeys: vec![vec![0u8; 48]; 512],
                aggregate_pubkey: vec![0u8; 48],
            },
            next_sync_committee: None,
            bootstrap_slot: 100,
            bootstrap_header_hash: [4u8; 32],
            initialized: true,
            current_execution_block_hash: [0u8; 32],
            current_execution_state_root: [0u8; 32],
            current_receipts_root: [0u8; 32],
            network_config: None,
        };

        assert!(instance.validate_authenticity().is_ok());

        // Uninitialized rejects
        instance.initialized = false;
        assert!(instance.validate_authenticity().is_err());
        instance.initialized = true;

        // Zero bootstrap slot rejects
        instance.bootstrap_slot = 0;
        assert!(instance.validate_authenticity().is_err());
        instance.bootstrap_slot = 100;

        // Zero bootstrap header hash rejects
        instance.bootstrap_header_hash = [0u8; 32];
        assert!(instance.validate_authenticity().is_err());
        instance.bootstrap_header_hash = [4u8; 32];

        // Slot progression inverted rejects
        instance.current_slot = 50;
        instance.bootstrap_slot = 100;
        assert!(instance.validate_authenticity().is_err());
    }
}
