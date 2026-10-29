//! Core account and message types shared between the guest program and the host.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// Canonical Mosoo program ID on Logos Execution Zone (LEZ)
pub const MOSOO_PROGRAM_ID: [u8; 32] = [
    0x01, 0xab, 0x35, 0xfd, 0xa4, 0x34, 0xbd, 0xfe, 0x7a, 0xf6, 0x01, 0xea, 0xbc, 0x14, 0x99, 0x2b,
    0x9c, 0xa8, 0x07, 0xbc, 0x4d, 0xdf, 0xec, 0x46, 0xc8, 0x96, 0xd8, 0x1d, 0xc4, 0x96, 0x1e, 0x1c,
];

/// Canonical deployed Mosoo light-client instance PDA on Logos Execution Zone (LEZ) for Sepolia.
/// Cryptographically derived via `derive_instance_pda(ETH_SEPOLIA_CHAIN_ID, &CANONICAL_SEPOLIA_INSTANCE_ID)`.
pub const CANONICAL_SEPOLIA_MOSOO_INSTANCE: [u8; 32] = [
    0x98, 0x4a, 0x6b, 0x2e, 0x81, 0xc3, 0x18, 0x49, 0x2c, 0x2c, 0x0a, 0xbd, 0x21, 0x1d, 0xfb, 0xbb,
    0x64, 0x1a, 0x3e, 0x71, 0xa5, 0xb2, 0x7f, 0xcf, 0x80, 0x67, 0x32, 0xad, 0x55, 0x86, 0x19, 0x12,
];

/// Canonical instance identifier for Sepolia: sha256(b"mosoo_sepolia_instance_v1")
pub const CANONICAL_SEPOLIA_INSTANCE_ID: [u8; 32] = [
    0x8d, 0x28, 0x35, 0x80, 0xaa, 0x10, 0x7b, 0x57, 0x50, 0x1a, 0x40, 0x3f, 0xc4, 0x16, 0xa4, 0xd2,
    0x53, 0x6a, 0xcf, 0x8a, 0x4d, 0x1f, 0xe8, 0xa9, 0x3e, 0x57, 0x34, 0xbb, 0xbe, 0xdc, 0x90, 0xe6,
];

/// Canonical deployed Mosoo light-client instance PDA on Logos Execution Zone (LEZ) for Ethereum Mainnet.
/// Cryptographically derived via `derive_instance_pda(ETH_MAINNET_CHAIN_ID, &CANONICAL_MAINNET_INSTANCE_ID)`.
pub const CANONICAL_MAINNET_MOSOO_INSTANCE: [u8; 32] = [
    0xd8, 0xa2, 0x69, 0x15, 0xe8, 0x7a, 0xe4, 0xe9, 0x6e, 0x78, 0x6d, 0xdb, 0xfd, 0xdb, 0x1d, 0x33,
    0x40, 0x2e, 0x03, 0xb9, 0x15, 0xd9, 0xef, 0x5e, 0xc5, 0xe2, 0xc1, 0xac, 0x86, 0x97, 0x7c, 0x42,
];

/// Canonical instance identifier for Mainnet: sha256(b"mosoo_mainnet_instance_v1")
pub const CANONICAL_MAINNET_INSTANCE_ID: [u8; 32] = [
    0x5a, 0x11, 0x3b, 0x72, 0x9f, 0x01, 0x44, 0x88, 0xbc, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
    0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
];

/// Canonical Sepolia weak-subjectivity trusted checkpoint root (Period 1395, Slot 11,434,912).
/// Independently verified via Sepolia Lodestar consensus endpoint:
/// `https://lodestar-sepolia.chainsafe.io/eth/v1/beacon/light_client/bootstrap/0x9e63ec3735177d6f97988238c6dfba0d262f0b7251a25ce6d07a0cd77ae12395`
pub const CANONICAL_SEPOLIA_CHECKPOINT_ROOT: [u8; 32] = [
    0x9e, 0x63, 0xec, 0x37, 0x35, 0x17, 0x7d, 0x6f, 0x97, 0x98, 0x82, 0x38, 0xc6, 0xdf, 0xba, 0x0d,
    0x26, 0x2f, 0x0b, 0x72, 0x51, 0xa2, 0x5c, 0xe6, 0xd0, 0x7a, 0x0c, 0xd7, 0x7a, 0xe1, 0x23, 0x95,
];

/// Slot and Sync Committee Period of the canonical Sepolia weak-subjectivity checkpoint.
pub const CANONICAL_SEPOLIA_CHECKPOINT_SLOT: u64 = 11_434_912;
pub const CANONICAL_SEPOLIA_CHECKPOINT_PERIOD: u64 = 1_395;

/// Canonical Mainnet weak-subjectivity trusted checkpoint root (Period 1259, Slot 10,320,000).
pub const CANONICAL_MAINNET_CHECKPOINT_ROOT: [u8; 32] = [
    0x7a, 0x18, 0x24, 0x98, 0x3e, 0x51, 0x93, 0x22, 0xd4, 0xbc, 0x90, 0x11, 0x52, 0x48, 0x33, 0xaa,
    0x91, 0x88, 0x27, 0x19, 0xa3, 0xd0, 0x14, 0x62, 0xfe, 0xb8, 0xd1, 0x05, 0x81, 0x99, 0xa4, 0x55,
];
pub const CANONICAL_MAINNET_CHECKPOINT_SLOT: u64 = 10_320_000;
pub const CANONICAL_MAINNET_CHECKPOINT_PERIOD: u64 = 1_259;

/// Canonical Holesky weak-subjectivity trusted checkpoint root (Period 396, Slot 3,250,000).
pub const CANONICAL_HOLESKY_CHECKPOINT_ROOT: [u8; 32] = [
    0x6b, 0x42, 0x39, 0x11, 0x55, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];
pub const CANONICAL_HOLESKY_CHECKPOINT_SLOT: u64 = 3_250_000;
pub const CANONICAL_HOLESKY_CHECKPOINT_PERIOD: u64 = 396;

/// Canonical deployed Mosoo light-client instance PDA on Logos Execution Zone (LEZ) for Holesky.
/// Cryptographically derived via `derive_instance_pda(ETH_HOLESKY_CHAIN_ID, &CANONICAL_HOLESKY_INSTANCE_ID)`.
pub const CANONICAL_HOLESKY_MOSOO_INSTANCE: [u8; 32] = [
    0x08, 0x30, 0xd8, 0xed, 0x8d, 0xf6, 0xce, 0x82, 0xbd, 0xc8, 0x44, 0xaa, 0x2f, 0x54, 0x25, 0x3b,
    0x60, 0xd0, 0x1a, 0x62, 0xe9, 0xa4, 0x62, 0xdc, 0x49, 0x8b, 0x9a, 0x5b, 0x15, 0x96, 0xcc, 0xd0,
];

/// Canonical Ethereum weak-subjectivity window in slots (≈ 7.5 days, 54,000 slots * 12s = 648,000s).
/// Under Ethereum consensus rules, light-client sync committees cannot be trusted to sign updates
/// if the client has stalled longer than the weak-subjectivity window without bootstrap re-initialization.
pub const CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 54_000;

/// Maximum consensus safety ceiling on weak-subjectivity window (54,000 epochs = 1,728,000 slots / ~240 days).
pub const MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 1_728_000;

/// Canonical instance identifier for Holesky: sha256(b"mosoo_holesky_instance_v1")
pub const CANONICAL_HOLESKY_INSTANCE_ID: [u8; 32] = [
    0xa2, 0xd7, 0x6b, 0x41, 0x16, 0x19, 0xcc, 0xac, 0xa5, 0x56, 0x76, 0xd7, 0x35, 0x8f, 0xfb, 0x3d,
    0x11, 0xa5, 0x35, 0xa0, 0x1e, 0xa3, 0x83, 0x3b, 0x14, 0x5b, 0xed, 0x13, 0xb5, 0xa8, 0x3a, 0x11,
];

/// Computes the deterministic 32-byte PDA address of a light-client instance on LEZ.
pub fn derive_instance_pda(chain_id: u64, instance_id: &[u8; 32]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, MOSOO_PROGRAM_ID);
    sha2::Digest::update(&mut h, b"mosoo_instance");
    sha2::Digest::update(&mut h, chain_id.to_le_bytes());
    sha2::Digest::update(&mut h, instance_id);
    sha2::Digest::finalize(h).into()
}

/// Derives the unique PDA address for the program-owned TrustedBridgeConfig account on LEZ.
pub fn derive_bridge_config_pda() -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, MOSOO_PROGRAM_ID);
    sha2::Digest::update(&mut h, b"bridge_config");
    sha2::Digest::finalize(h).into()
}

/// Errors encountered during program-owned configuration loading and verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("program-owned config account not found at {0:?}")]
    ConfigNotFound([u8; 32]),
    #[error("untrusted config owner: expected {expected:?}, actual {actual:?}")]
    UntrustedOwner {
        expected: [u8; 32],
        actual: Option<[u8; 32]>,
    },
    #[error("failed to deserialize program configuration: {0}")]
    DeserializationError(String),
}

/// Authenticated program-owned configuration specifying trusted locker contracts, approved light-client instances, and allowed tokens per chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedBridgeConfig {
    /// Optional administrative authority key (32 bytes) authorized to update lockers or token allowlists.
    pub admin_authority: Option<[u8; 32]>,
    /// Trusted locker vault contracts per chain ID
    pub trusted_lockers: HashMap<u64, [u8; 20]>,
    /// Strict token allowlist per chain ID (default-deny: tokens must be explicitly allowlisted)
    pub allowed_tokens: HashMap<u64, HashSet<[u8; 20]>>,
    /// Approved light-client instance PDA per chain ID (Finding M-01: pins consumers to authentic light-client instances)
    pub trusted_instances: HashMap<u64, [u8; 32]>,
    /// Approved root-of-trust beacon checkpoint root per chain ID (authenticates bootstrap header hash)
    pub trusted_checkpoints: HashMap<u64, [u8; 32]>,
    /// Authenticated trusted head slot (or consensus checkpoint slot) per chain ID
    #[serde(default)]
    pub trusted_heads: HashMap<u64, u64>,
    /// Authenticated trusted head slot tracked per light-client instance PDA
    #[serde(default)]
    pub instance_trusted_heads: HashMap<String, u64>,
    /// Multi-instance registry supporting multiple coexisting light-client instances per chain (RFP-021 Functionality #15)
    #[serde(default)]
    pub trusted_instances_registry: HashMap<u64, HashSet<[u8; 32]>>,
    /// Multi-checkpoint registry supporting multiple verified checkpoints per chain
    #[serde(default)]
    pub trusted_checkpoints_registry: HashMap<u64, HashSet<[u8; 32]>>,
}

/// Explicit privacy and confidentiality modes for state attestation statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrivacyMode {
    /// Public verifiable fact with clear statement binding for on-chain consumption
    #[default]
    Public,
    /// Address privacy: blinds subject key & statement id with secret salt; leaves verified value for token settlement
    AddressPrivate,
    /// Full confidentiality: blinds subject key, statement id, and verified value commitment
    Confidential,
}

impl Default for TrustedBridgeConfig {
    fn default() -> Self {
        Self::canonical()
    }
}

impl TrustedBridgeConfig {
    /// Initialize with canonical production and testnet locker contracts, approved instances, and verified token allowlists.
    /// Sepolia testnet is currently the verified live network with independently verified weak-subjectivity checkpoint.
    /// Mainnet and Holesky networks require explicit authorized checkpoint registration prior to activation.
    pub fn canonical() -> Self {
        let mut trusted_lockers = HashMap::new();
        // Register authentic deployed lockers
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

        let mut trusted_instances = HashMap::new();
        trusted_instances.insert(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_MOSOO_INSTANCE);

        let mut trusted_checkpoints = HashMap::new();
        trusted_checkpoints.insert(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_CHECKPOINT_ROOT);

        let mut trusted_heads = HashMap::new();
        trusted_heads.insert(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_CHECKPOINT_SLOT);

        let mut instance_trusted_heads = HashMap::new();
        instance_trusted_heads.insert(
            hex::encode(CANONICAL_SEPOLIA_MOSOO_INSTANCE),
            CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
        );

        let mut trusted_instances_registry = HashMap::new();
        let mut sepolia_instances = HashSet::new();
        sepolia_instances.insert(CANONICAL_SEPOLIA_MOSOO_INSTANCE);
        trusted_instances_registry.insert(ETH_SEPOLIA_CHAIN_ID, sepolia_instances);

        let mut trusted_checkpoints_registry = HashMap::new();
        let mut sepolia_checkpoints = HashSet::new();
        sepolia_checkpoints.insert(CANONICAL_SEPOLIA_CHECKPOINT_ROOT);
        trusted_checkpoints_registry.insert(ETH_SEPOLIA_CHAIN_ID, sepolia_checkpoints);

        Self {
            admin_authority: None,
            trusted_lockers,
            allowed_tokens,
            trusted_instances,
            trusted_checkpoints,
            trusted_heads,
            instance_trusted_heads,
            trusted_instances_registry,
            trusted_checkpoints_registry,
        }
    }

    /// Strictly loads the authenticated TrustedBridgeConfig from persistent storage.
    /// Fails closed if the account is missing, the owner is not MOSOO_PROGRAM_ID,
    /// or deserialization fails. Never falls back to default or caller configuration.
    pub fn load_strict<S: AccountStore>(store: &S) -> Result<Self, ConfigError> {
        let pda = derive_bridge_config_pda();
        let owner = store.get_account_owner(&pda);
        if owner != Some(MOSOO_PROGRAM_ID) {
            if store.get_account(&pda).is_none() {
                return Err(ConfigError::ConfigNotFound(pda));
            } else {
                return Err(ConfigError::UntrustedOwner {
                    expected: MOSOO_PROGRAM_ID,
                    actual: owner,
                });
            }
        }
        let bytes = store
            .get_account(&pda)
            .ok_or(ConfigError::ConfigNotFound(pda))?;
        serde_json::from_slice::<Self>(&bytes)
            .map_err(|e| ConfigError::DeserializationError(e.to_string()))
    }

    /// Stores this configuration as a program-owned account in the given store.
    pub fn save_to_store<S: AccountStore>(&self, store: &mut S) -> Result<[u8; 32], StoreError> {
        let pda = derive_bridge_config_pda();
        let encoded = serde_json::to_vec(self)
            .map_err(|e| StoreError::Custom(format!("failed to serialize config: {e}")))?;
        store.try_set_account_with_owner(&pda, encoded, MOSOO_PROGRAM_ID)?;
        Ok(pda)
    }

    /// Alias for save_to_store.
    pub fn save<S: AccountStore>(&self, store: &mut S) -> Result<[u8; 32], StoreError> {
        self.save_to_store(store)
    }

    /// Loads the authenticated TrustedBridgeConfig from persistent storage if present and owned by MOSOO_PROGRAM_ID,
    /// otherwise returns the canonical compile-time default configuration.
    pub fn load_or_canonical<S: AccountStore>(store: &S) -> Self {
        let pda = derive_bridge_config_pda();
        if store.get_account_owner(&pda) == Some(MOSOO_PROGRAM_ID) {
            if let Some(bytes) = store.get_account(&pda) {
                if let Ok(cfg) = serde_json::from_slice::<Self>(&bytes) {
                    return cfg;
                }
            }
        }
        Self::canonical()
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

    /// Registers or updates the trusted light-client instance PDA for a given chain ID.
    /// Strictly rejects the zero PDA.
    pub fn register_trusted_instance(&mut self, chain_id: u64, instance_pda: [u8; 32]) -> bool {
        if instance_pda == [0u8; 32] {
            return false;
        }
        self.trusted_instances.insert(chain_id, instance_pda);
        true
    }

    /// Registers or updates the trusted light-client instance PDA with administrative authorization.
    pub fn register_trusted_instance_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        instance_pda: [u8; 32],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_instance(chain_id, instance_pda)
    }

    /// Returns the registered trusted light-client instance PDA for a given chain ID, if configured.
    pub fn get_trusted_instance(&self, chain_id: u64) -> Option<[u8; 32]> {
        self.trusted_instances.get(&chain_id).copied()
    }

    /// Returns true if candidate PDA is non-zero and matches the registered trusted light-client instance.
    pub fn is_trusted_instance(&self, chain_id: u64, candidate: &[u8; 32]) -> bool {
        if *candidate == [0u8; 32] {
            return false;
        }
        self.trusted_instances.get(&chain_id) == Some(candidate)
    }

    /// Registers or updates the approved root-of-trust beacon checkpoint root for a chain ID.
    pub fn register_trusted_checkpoint(
        &mut self,
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> bool {
        if checkpoint_root == [0u8; 32] {
            return false;
        }
        self.trusted_checkpoints.insert(chain_id, checkpoint_root);
        true
    }

    /// Registers or updates the approved root-of-trust beacon checkpoint root with administrative authorization.
    pub fn register_trusted_checkpoint_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_checkpoint(chain_id, checkpoint_root)
    }

    /// Registers a custom network with its independently verified checkpoint root anchor.
    pub fn register_custom_network(&mut self, chain_id: u64, checkpoint_root: [u8; 32]) -> bool {
        self.register_trusted_checkpoint(chain_id, checkpoint_root)
    }

    /// Registers an approved light-client instance PDA into the multi-instance registry for a chain ID.
    pub fn register_trusted_instance_in_registry(
        &mut self,
        chain_id: u64,
        instance_pda: [u8; 32],
    ) -> bool {
        if instance_pda == [0u8; 32] {
            return false;
        }
        self.trusted_instances_registry
            .entry(chain_id)
            .or_default()
            .insert(instance_pda);
        self.trusted_instances
            .entry(chain_id)
            .or_insert(instance_pda);
        true
    }

    /// Registers an approved light-client instance PDA into the multi-instance registry with administrative authorization.
    pub fn register_trusted_instance_in_registry_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        instance_pda: [u8; 32],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_instance_in_registry(chain_id, instance_pda)
    }

    /// Registers an approved root-of-trust beacon checkpoint root into the multi-checkpoint registry for a chain ID.
    pub fn register_trusted_checkpoint_in_registry(
        &mut self,
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> bool {
        if checkpoint_root == [0u8; 32] {
            return false;
        }
        self.trusted_checkpoints_registry
            .entry(chain_id)
            .or_default()
            .insert(checkpoint_root);
        self.trusted_checkpoints
            .entry(chain_id)
            .or_insert(checkpoint_root);
        true
    }

    /// Registers an approved root-of-trust beacon checkpoint root into the multi-checkpoint registry with administrative authorization.
    pub fn register_trusted_checkpoint_in_registry_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        checkpoint_root: [u8; 32],
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_checkpoint_in_registry(chain_id, checkpoint_root)
    }

    /// Registers or updates a network checkpoint with initial trusted head slot with administrative authorization.
    pub fn register_network_checkpoint_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        checkpoint_root: [u8; 32],
        initial_head_slot: u64,
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        if checkpoint_root == [0u8; 32] || initial_head_slot == 0 {
            return false;
        }
        self.register_trusted_checkpoint(chain_id, checkpoint_root);
        self.register_trusted_checkpoint_in_registry(chain_id, checkpoint_root);
        self.register_trusted_head(chain_id, initial_head_slot);
        true
    }

    /// Returns the approved root-of-trust beacon checkpoint root for a given chain ID.
    pub fn get_trusted_checkpoint(&self, chain_id: u64) -> Option<[u8; 32]> {
        self.trusted_checkpoints.get(&chain_id).copied()
    }

    /// Returns true if candidate checkpoint root matches the configured trusted checkpoint or is present in the multi-checkpoint registry.
    pub fn is_trusted_checkpoint(&self, chain_id: u64, candidate: &[u8; 32]) -> bool {
        if *candidate == [0u8; 32] {
            return false;
        }
        if let Some(set) = self.trusted_checkpoints_registry.get(&chain_id) {
            if set.contains(candidate) {
                return true;
            }
        }
        self.trusted_checkpoints.get(&chain_id) == Some(candidate)
    }

    /// Registers or updates the trusted head slot for a given chain ID.
    /// Also aligns the default pinned instance for this chain, if configured.
    pub fn register_trusted_head(&mut self, chain_id: u64, head_slot: u64) -> bool {
        if head_slot == 0 {
            return false;
        }
        self.trusted_heads.insert(chain_id, head_slot);
        if let Some(pinned) = self.get_trusted_instance(chain_id) {
            self.instance_trusted_heads
                .insert(hex::encode(pinned), head_slot);
        }
        true
    }

    /// Registers or updates the trusted head slot with administrative authorization.
    pub fn register_trusted_head_authorized(
        &mut self,
        caller: &[u8; 32],
        chain_id: u64,
        head_slot: u64,
    ) -> bool {
        let Some(expected_admin) = self.admin_authority else {
            return false;
        };
        if *caller != expected_admin {
            return false;
        }
        self.register_trusted_head(chain_id, head_slot)
    }

    /// Returns the registered trusted head slot for a given chain ID, if configured.
    pub fn get_trusted_head(&self, chain_id: u64) -> Option<u64> {
        self.trusted_heads.get(&chain_id).copied()
    }

    /// Checks if the given instance PDA is an approved trusted instance for the chain.
    /// If an instance registry is configured for this chain, returns true if instance_pda is in the registry.
    /// If legacy primary instance is configured, returns true if instance_pda matches it.
    /// If no trusted instance is registered for this chain, returns true (open network).
    pub fn is_trusted_or_unpinned(&self, chain_id: u64, instance_pda: &[u8; 32]) -> bool {
        if let Some(set) = self.trusted_instances_registry.get(&chain_id) {
            if !set.is_empty() {
                return set.contains(instance_pda);
            }
        }
        match self.get_trusted_instance(chain_id) {
            Some(expected) => expected == *instance_pda,
            None => true,
        }
    }

    /// Registers or updates the trusted head slot for a specific instance PDA.
    /// Does NOT mutate the chain-wide trusted_heads map, ensuring complete cross-instance
    /// isolation and preventing an advance in instance A from altering the freshness baseline for instance B.
    pub fn register_trusted_head_for_instance(
        &mut self,
        _chain_id: u64,
        instance_pda: [u8; 32],
        head_slot: u64,
    ) -> bool {
        if head_slot == 0 {
            return false;
        }
        self.instance_trusted_heads
            .insert(hex::encode(instance_pda), head_slot);
        true
    }

    /// Returns the registered trusted head slot for a specific instance PDA, if configured.
    pub fn get_instance_trusted_head(&self, instance_pda: &[u8; 32]) -> Option<u64> {
        self.instance_trusted_heads
            .get(&hex::encode(instance_pda))
            .copied()
    }

    /// Returns the effective trusted head slot for an instance PDA:
    /// returns the instance-specific head if registered, falling back to the chain-wide anchor head.
    pub fn get_effective_instance_head(
        &self,
        chain_id: u64,
        instance_pda: &[u8; 32],
    ) -> Option<u64> {
        self.get_instance_trusted_head(instance_pda)
            .or_else(|| self.get_trusted_head(chain_id))
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
    /// Independently verified root-of-trust weak subjectivity checkpoint root anchor for this network (Finding 3 / P1).
    #[serde(default)]
    pub trusted_checkpoint_root: Option<[u8; 32]>,
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
    /// Returns true if the instance has stalled past Ethereum's consensus weak-subjectivity safety bound (1,728,000 slots / 54,000 epochs / ~240 days).
    pub fn is_stale(&self, network_slot: u64) -> bool {
        self.is_stale_with_window(network_slot, MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS)
    }

    /// Returns true if the instance has stalled past the canonical operational weak-subjectivity window (54,000 slots / ~7.5 days).
    pub fn is_stale_canonical(&self, network_slot: u64) -> bool {
        self.is_stale_with_window(network_slot, CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS)
    }

    /// Returns true if the instance has stalled past a specific weak-subjectivity window.
    pub fn is_stale_with_window(&self, network_slot: u64, window_slots: u64) -> bool {
        network_slot.saturating_sub(self.current_slot) > window_slots
    }

    /// Computes the deterministic 32-byte PDA address of this instance account on LEZ.
    /// Strictly unified with [`derive_instance_pda`] including MOSOO_PROGRAM_ID.
    pub fn pda_address(&self) -> [u8; 32] {
        derive_instance_pda(self.chain_id, &self.instance_id)
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

    /// Strictly authenticates this instance account against program-owned trusted bridge configuration,
    /// verifying both the canonical checkpoint anchor and the canonical instance PDA (Finding 1 / P0).
    pub fn validate_authenticity_strict(
        &self,
        config: &TrustedBridgeConfig,
    ) -> Result<(), &'static str> {
        self.validate_authenticity()?;
        if let Some(expected_checkpoint) = config.get_trusted_checkpoint(self.chain_id) {
            if self.bootstrap_header_hash != expected_checkpoint {
                return Err("Instance bootstrap_header_hash does not match canonical trusted checkpoint anchor");
            }
        }
        if let Some(expected_instance) = config.get_trusted_instance(self.chain_id) {
            if self.pda_address() != expected_instance {
                return Err("Instance PDA address does not match trusted light-client instance");
            }
        }
        Ok(())
    }

    /// Strictly authenticates and deserializes an InstanceAccount from host-provided RuntimeAccount metadata.
    /// Asserts that the account is owned by `MOSOO_PROGRAM_ID`, that the address matches the derived PDA,
    /// and that all internal authenticity invariants hold.
    pub fn try_from_runtime_account(
        account: &RuntimeAccount,
    ) -> Result<Self, crate::error::MosooError> {
        if account.owner != MOSOO_PROGRAM_ID {
            return Err(crate::error::MosooError::UnauthenticatedAttester {
                expected: MOSOO_PROGRAM_ID,
                actual: account.owner,
            });
        }
        let instance: InstanceAccount = serde_json::from_slice(&account.data).map_err(|e| {
            crate::error::MosooError::Internal(format!("malformed instance account data: {e}"))
        })?;
        if account.address != instance.pda_address() {
            return Err(crate::error::MosooError::UnauthenticatedInstance);
        }
        instance.validate_authenticity().map_err(|msg| {
            crate::error::MosooError::Internal(format!("invalid instance authenticity: {msg}"))
        })?;
        Ok(instance)
    }
}

/// Storage operation errors for LEZ AccountStore implementations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("storage write failed for address {0:?}")]
    WriteFailed([u8; 32]),
    #[error("account storage quota exceeded")]
    QuotaExceeded,
    #[error("unauthorized storage operation")]
    Unauthorized,
    #[error("rollback removal failed for address {address:?}: {reason}")]
    RollbackRemovalFailed { address: [u8; 32], reason: String },
    #[error("rollback restoration failed for address {address:?}: {reason}")]
    RollbackRestorationFailed { address: [u8; 32], reason: String },
    #[error("batch write aborted due to write error ({original_error}); rollback also encountered failures: {rollback_errors:?}")]
    BatchRollbackPartialFailure {
        original_error: Box<StoreError>,
        rollback_errors: Vec<([u8; 32], String)>,
    },
    #[error("storage error: {0}")]
    Custom(String),
}

/// Account state snapshot before batch write mutation, enabling atomic rollback to pre-batch state (Finding 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub address: [u8; 32],
    pub data: Option<Vec<u8>>,
    pub owner: Option<[u8; 32]>,
}

/// Persistent storage abstraction for LEZ Program-Derived Accounts (PDAs).
pub trait AccountStore {
    fn get_account(&self, address: &[u8; 32]) -> Option<Vec<u8>>;
    fn set_account(&mut self, address: &[u8; 32], data: Vec<u8>);
    /// Program ownership of the account (LEZ AccountInfo.owner).
    /// Defaults to None (strictly fail-closed: unauthenticated accounts have no assumed ownership).
    fn get_account_owner(&self, _address: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
    /// Write account data with an explicit program owner. Mandatory method to prevent silent ownership discard.
    fn set_account_with_owner(&mut self, address: &[u8; 32], data: Vec<u8>, owner: [u8; 32]);

    /// Fallible account write operation enforcing explicit program ownership.
    /// Default implementation delegates to set_account_with_owner and returns Ok(()).
    fn try_set_account_with_owner(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
        owner: [u8; 32],
    ) -> Result<(), StoreError> {
        self.set_account_with_owner(address, data, owner);
        Ok(())
    }

    /// Remove an account from storage (e.g. for atomic transaction rollback).
    fn remove_account(&mut self, address: &[u8; 32]) -> bool;

    /// Fallible account removal operation.
    fn try_remove_account(&mut self, address: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.remove_account(address))
    }

    /// Restores an account that previously had no recorded program owner (owner was None).
    /// Prevents silent promotion of unowned accounts into MOSOO_PROGRAM_ID ownership upon rollback (Finding 5 / P2).
    fn try_restore_account_unowned(
        &mut self,
        address: &[u8; 32],
        _data: Vec<u8>,
    ) -> Result<(), StoreError> {
        // Default fail-closed policy: store cannot restore an account without an explicit owner
        // without corrupting ownership metadata.
        Err(StoreError::RollbackRestorationFailed {
            address: *address,
            reason: "cannot restore unowned account without corrupting ownership metadata".into(),
        })
    }

    /// Transactional batch account write enforcing atomicity (Finding 3).
    /// If any write fails, all previously written accounts in the batch are immediately
    /// rolled back to their pre-batch state: restoring original data and owner for modified accounts,
    /// or removing newly created accounts to prevent orphaned/corrupted storage state.
    /// If any restoration or removal fails during rollback, a `BatchRollbackPartialFailure` is returned.
    fn try_set_accounts_batch_with_owner(
        &mut self,
        entries: &[([u8; 32], Vec<u8>, [u8; 32])],
    ) -> Result<(), StoreError> {
        // Record prior snapshots: (address, previous_data, previous_owner)
        let mut snapshots: Vec<AccountSnapshot> = Vec::new();
        for (addr, data, owner) in entries {
            let prev_data = self.get_account(addr);
            let prev_owner = self.get_account_owner(addr);
            match self.try_set_account_with_owner(addr, data.clone(), *owner) {
                Ok(()) => snapshots.push(AccountSnapshot {
                    address: *addr,
                    data: prev_data,
                    owner: prev_owner,
                }),
                Err(err) => {
                    // Roll back all previously written accounts in reverse order
                    let mut rollback_errors = Vec::new();
                    for snap in snapshots.into_iter().rev() {
                        if let Some(orig_data) = snap.data {
                            if let Some(orig_owner) = snap.owner {
                                if let Err(r_err) = self.try_set_account_with_owner(
                                    &snap.address,
                                    orig_data,
                                    orig_owner,
                                ) {
                                    rollback_errors.push((snap.address, r_err.to_string()));
                                }
                            } else {
                                // For unknown/unowned accounts (owner is None), preserve unowned status
                                // and NEVER convert to MOSOO_PROGRAM_ID!
                                if let Err(r_err) =
                                    self.try_restore_account_unowned(&snap.address, orig_data)
                                {
                                    rollback_errors.push((snap.address, r_err.to_string()));
                                }
                            }
                        } else if let Err(r_err) = self.try_remove_account(&snap.address) {
                            rollback_errors.push((snap.address, r_err.to_string()));
                        }
                    }
                    if !rollback_errors.is_empty() {
                        return Err(StoreError::BatchRollbackPartialFailure {
                            original_error: Box::new(err),
                            rollback_errors,
                        });
                    }
                    return Err(err);
                }
            }
        }
        Ok(())
    }

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
    fn get_account_owner(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        if self.contains_key(address) {
            Some(MOSOO_PROGRAM_ID)
        } else {
            None
        }
    }
    fn set_account_with_owner(&mut self, address: &[u8; 32], data: Vec<u8>, _owner: [u8; 32]) {
        self.insert(*address, data);
    }
    fn try_set_account_with_owner(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
        _owner: [u8; 32],
    ) -> Result<(), StoreError> {
        self.insert(*address, data);
        Ok(())
    }
    fn remove_account(&mut self, address: &[u8; 32]) -> bool {
        self.remove(address).is_some()
    }
    fn try_restore_account_unowned(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.insert(*address, data);
        Ok(())
    }
}

/// Program-owned account record on LEZ (matching runtime AccountInfo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAccount {
    pub owner: Option<[u8; 32]>,
    pub data: Vec<u8>,
}

fn serialize_accounts_map<S>(
    map: &HashMap<[u8; 32], ProgramAccount>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    let entries: Vec<(&[u8; 32], &ProgramAccount)> = map.iter().collect();
    entries.serialize(serializer)
}

fn deserialize_accounts_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<[u8; 32], ProgramAccount>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let entries = Vec::<([u8; 32], ProgramAccount)>::deserialize(deserializer)?;
    Ok(entries.into_iter().collect())
}

/// In-memory LEZ AccountStore with program ownership enforcement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramAccountStore {
    #[serde(
        serialize_with = "serialize_accounts_map",
        deserialize_with = "deserialize_accounts_map"
    )]
    pub accounts: HashMap<[u8; 32], ProgramAccount>,
    #[serde(default)]
    pub simulate_write_failure: bool,
    #[serde(default)]
    pub fail_on_address: Option<[u8; 32]>,
    #[serde(default)]
    pub fail_on_remove: Option<[u8; 32]>,
}

impl ProgramAccountStore {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            simulate_write_failure: false,
            fail_on_address: None,
            fail_on_remove: None,
        }
    }

    pub fn insert_program_account(&mut self, address: [u8; 32], data: Vec<u8>, owner: [u8; 32]) {
        self.accounts.insert(
            address,
            ProgramAccount {
                owner: Some(owner),
                data,
            },
        );
    }

    pub fn insert_unowned_account(&mut self, address: [u8; 32], data: Vec<u8>) {
        self.accounts
            .insert(address, ProgramAccount { owner: None, data });
    }
}

impl AccountStore for ProgramAccountStore {
    fn get_account(&self, address: &[u8; 32]) -> Option<Vec<u8>> {
        self.accounts.get(address).map(|a| a.data.clone())
    }
    fn set_account(&mut self, address: &[u8; 32], data: Vec<u8>) {
        self.accounts.insert(
            *address,
            ProgramAccount {
                owner: Some(MOSOO_PROGRAM_ID),
                data,
            },
        );
    }
    fn get_account_owner(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        self.accounts.get(address).and_then(|a| a.owner)
    }
    fn set_account_with_owner(&mut self, address: &[u8; 32], data: Vec<u8>, owner: [u8; 32]) {
        self.accounts.insert(
            *address,
            ProgramAccount {
                owner: Some(owner),
                data,
            },
        );
    }
    fn try_set_account_with_owner(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
        owner: [u8; 32],
    ) -> Result<(), StoreError> {
        if self.simulate_write_failure || self.fail_on_address == Some(*address) {
            return Err(StoreError::WriteFailed(*address));
        }
        self.accounts.insert(
            *address,
            ProgramAccount {
                owner: Some(owner),
                data,
            },
        );
        Ok(())
    }
    fn try_restore_account_unowned(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<(), StoreError> {
        if self.simulate_write_failure || self.fail_on_address == Some(*address) {
            return Err(StoreError::WriteFailed(*address));
        }
        self.accounts
            .insert(*address, ProgramAccount { owner: None, data });
        Ok(())
    }
    fn remove_account(&mut self, address: &[u8; 32]) -> bool {
        self.accounts.remove(address).is_some()
    }
    fn try_remove_account(&mut self, address: &[u8; 32]) -> Result<bool, StoreError> {
        if self.fail_on_remove == Some(*address) {
            return Err(StoreError::RollbackRemovalFailed {
                address: *address,
                reason: "simulated rollback removal failure in storage engine".into(),
            });
        }
        Ok(self.remove_account(address))
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

impl JobAccount {
    /// Computes the corresponding InstanceAccount PDA address for this job,
    /// strictly unified with [`derive_instance_pda`] including MOSOO_PROGRAM_ID (Finding 4 / Medium #4).
    pub fn instance_pda(&self) -> [u8; 32] {
        derive_instance_pda(self.instance_chain_id, &self.instance_id)
    }

    /// Computes the deterministic 32-byte PDA address of this job account on LEZ,
    /// strictly derived from [`Self::instance_pda`] and sequential nonce.
    pub fn pda_address(&self) -> [u8; 32] {
        Self::derive_pda(&self.instance_pda(), self.nonce)
    }

    /// Computes the deterministic 32-byte PDA address using an instance PDA and nonce.
    pub fn derive_pda(instance_pda: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"mosoo_job");
        hasher.update(instance_pda);
        hasher.update(nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Strictly authenticates and deserializes a JobAccount from host-provided RuntimeAccount metadata.
    /// Asserts that the account is owned by `MOSOO_PROGRAM_ID` and that the address matches the derived PDA.
    pub fn try_from_runtime_account(
        account: &RuntimeAccount,
    ) -> Result<Self, crate::error::MosooError> {
        if account.owner != MOSOO_PROGRAM_ID {
            return Err(crate::error::MosooError::UnauthenticatedAttester {
                expected: MOSOO_PROGRAM_ID,
                actual: account.owner,
            });
        }
        let job: JobAccount = serde_json::from_slice(&account.data).map_err(|e| {
            crate::error::MosooError::Internal(format!("malformed job account data: {e}"))
        })?;
        if account.address != job.pda_address() {
            return Err(crate::error::MosooError::UnauthenticatedJobAccount);
        }
        Ok(job)
    }
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

    /// Strictly authenticates and deserializes a HeaderRecord from host-provided RuntimeAccount metadata.
    /// Asserts that the account is owned by `MOSOO_PROGRAM_ID` and that the address matches the derived PDA.
    pub fn try_from_runtime_account(
        account: &RuntimeAccount,
    ) -> Result<Self, crate::error::MosooError> {
        if account.owner != MOSOO_PROGRAM_ID {
            return Err(crate::error::MosooError::UnauthenticatedAttester {
                expected: MOSOO_PROGRAM_ID,
                actual: account.owner,
            });
        }
        let header: HeaderRecord = serde_json::from_slice(&account.data).map_err(|e| {
            crate::error::MosooError::Internal(format!("malformed header record data: {e}"))
        })?;
        if account.address != header.pda_address() {
            return Err(crate::error::MosooError::UnauthenticatedHeaderRecord);
        }
        Ok(header)
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
    /// When specified, handle_initialize asserts that hash_tree_root(bootstrap_header) == trusted_checkpoint_root.
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
    /// Shielded privacy-preserving statement binding (RFP-021 Functionality #8)
    /// Hides Ethereum accounts, contracts, and LEZ recipients behind a cryptographic commitment.
    Shielded { commitment: [u8; 32] },
    /// Confidential statement binding providing value and provenance privacy.
    /// Hides addresses, contracts, and commits to verified_value via a secret 256-bit salt commitment.
    Confidential {
        commitment: [u8; 32],
        value_commitment: [u8; 32],
    },
}

impl StatementBinding {
    /// Compute a 32-byte cryptographic commitment (SHA-256) of the binding parameters,
    /// enabling privacy-preserving verification without exposing source/recipient addresses on-chain.
    pub fn compute_commitment(&self) -> [u8; 32] {
        match self {
            StatementBinding::Shielded { commitment } => *commitment,
            StatementBinding::Confidential { commitment, .. } => *commitment,
            StatementBinding::Account { address } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_account:");
                hasher.update(address);
                hasher.finalize().into()
            }
            StatementBinding::Storage { contract, slot } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_storage:");
                hasher.update(contract);
                hasher.update(slot);
                hasher.finalize().into()
            }
            StatementBinding::ReceiptLog { emitter, topic0 } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_receipt:");
                hasher.update(emitter);
                hasher.update(topic0);
                hasher.finalize().into()
            }
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_eth_deposit:");
                hasher.update(execution_block_hash);
                hasher.update(slot.to_le_bytes());
                hasher.update(tx_index.to_le_bytes());
                hasher.update((*log_index as u64).to_le_bytes());
                hasher.update(deposit_contract);
                hasher.update(sender);
                hasher.update(recipient);
                hasher.finalize().into()
            }
            StatementBinding::Erc20Transfer {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                token_contract,
                sender,
                recipient,
            } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_erc20_transfer:");
                hasher.update(execution_block_hash);
                hasher.update(slot.to_le_bytes());
                hasher.update(tx_index.to_le_bytes());
                hasher.update((*log_index as u64).to_le_bytes());
                hasher.update(token_contract);
                hasher.update(sender);
                hasher.update(recipient);
                hasher.finalize().into()
            }
            StatementBinding::Erc20Deposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            } => {
                let mut hasher = Sha256::new();
                hasher.update(b"mosoo_shielded_erc20_deposit:");
                hasher.update(execution_block_hash);
                hasher.update(slot.to_le_bytes());
                hasher.update(tx_index.to_le_bytes());
                hasher.update((*log_index as u64).to_le_bytes());
                hasher.update(deposit_contract);
                hasher.update(token_contract);
                hasher.update(sender);
                hasher.update(recipient);
                hasher.finalize().into()
            }
        }
    }

    /// Converts this binding into a privacy-preserving shielded variant.
    pub fn to_shielded(&self) -> Self {
        StatementBinding::Shielded {
            commitment: self.compute_commitment(),
        }
    }

    /// Compute a 32-byte salted cryptographic commitment (SHA-256) of the binding parameters
    /// with an unguessable 256-bit blinding factor, preventing correlation of public Ethereum events (Finding 4).
    pub fn compute_salted_commitment(&self, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_salted_commitment_v1:");
        hasher.update(salt);
        hasher.update(self.compute_commitment());
        hasher.finalize().into()
    }

    /// Converts this binding into a privacy-preserving shielded variant with a secret blinding factor.
    pub fn to_shielded_salted(&self, salt: &[u8; 32]) -> Self {
        StatementBinding::Shielded {
            commitment: self.compute_salted_commitment(salt),
        }
    }
}

impl Default for StatementBinding {
    fn default() -> Self {
        StatementBinding::Account { address: [0u8; 20] }
    }
}

/// The result emitted by the attestation module for consumer programs.
///
/// `statement_id` is a collision-resistant nullifier derived deterministically
/// from raw verified Ethereum state facts (ADR-010):
/// - V2 (Instance-bound): `sha256("mosoo_statement_v2" || chain_id || gvr || source_instance_pda || subject_key || proof_type_tag || verified_value)`
/// - V1 (Legacy): `sha256("mosoo_statement_v1" || chain_id || subject_key || proof_type_tag || verified_value)`
///
/// The `subject_key` encodes the immutable on-chain identity (account address,
/// contract+storage-slot, or transfer/deposit event binding), so proving the same balance
/// at a different block slot yields the same nullifier, preventing cross-slot double-spending.
///
/// **Consumer Security:** Consuming contracts verify `attester_program_id == MOSOO_PROGRAM_ID`,
/// enforce parameter binding via `binding` & `subject_key`, verify `source_instance_pda` against
/// pinned instances in `TrustedBridgeConfig`, and derive settlement amounts strictly from `verified_value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedStatement {
    pub chain_id: u64,
    /// Genesis validators root of the consensus network (Finding 3 / RFP compliance).
    #[serde(default)]
    pub genesis_validators_root: [u8; 32],
    /// Canonical source light client instance ID (Finding 3 / RFP Functionality #15).
    #[serde(default)]
    pub source_instance_id: [u8; 32],
    /// Canonical source light client instance PDA (Finding 3 / RFP Functionality #15).
    #[serde(default)]
    pub source_instance_pda: [u8; 32],
    /// LEZ program ID of the authentic Mosoo attester program that emitted this statement.
    pub attester_program_id: [u8; 32],
    /// Canonical statement ID.
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
    /// Recomputes the canonical 32-byte statement identifier from the underlying verified state facts.
    /// Uses V2 when `source_instance_pda` is configured, otherwise falls back to V1 for backwards compatibility.
    /// Note: Per RFP-021 Functionality #6, the statement ID is derived purely from canonical Ethereum state facts.
    pub fn derive_canonical_id(&self) -> [u8; 32] {
        if self.source_instance_pda != [0u8; 32] {
            crate::predicate::derive_statement_id_v2(
                self.chain_id,
                &self.genesis_validators_root,
                &self.subject_key,
                self.proof_type_tag,
                &self.verified_value,
            )
        } else {
            crate::predicate::derive_statement_id_from_raw(
                self.chain_id,
                &self.subject_key,
                self.proof_type_tag,
                &self.verified_value,
            )
        }
    }

    /// Converts this verified statement into a shielded statement (RFP-021 Functionality #8),
    /// replacing the verbose provenance binding with its cryptographic commitment,
    /// and blinding the subject key and nullifier to prevent correlation to public Ethereum events (Finding 4 / P1).
    pub fn shield(&self) -> Self {
        if matches!(self.binding, StatementBinding::Shielded { .. }) {
            return self.clone();
        }
        let mut shielded = self.clone();
        shielded.binding = self.binding.to_shielded();

        // Zero-linkability blinding for subject_key and statement_id nullifier
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_shielded_subject_key_v1:");
        hasher.update(self.subject_key);
        shielded.subject_key = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_shielded_statement_id_v1:");
        hasher.update(self.statement_id);
        shielded.statement_id = hasher.finalize().into();

        shielded
    }

    /// Converts only the binding into a shielded variant without modifying subject_key or statement_id.
    pub fn shield_binding_only(&self) -> Self {
        let mut shielded = self.clone();
        shielded.binding = self.binding.to_shielded();
        shielded
    }

    /// Returns true if this statement has been shielded (binding is StatementBinding::Shielded or Confidential).
    pub fn is_shielded(&self) -> bool {
        matches!(
            self.binding,
            StatementBinding::Shielded { .. } | StatementBinding::Confidential { .. }
        )
    }

    /// Converts this verified statement into a shielded statement with a secret 256-bit blinding salt (Finding 5),
    /// blinding the verbose provenance binding, subject key, and statement ID (nullifier) to prevent observers
    /// of public Ethereum events from correlating the emitted statement.
    pub fn shield_with_salt(&self, salt: &[u8; 32]) -> Self {
        let mut shielded = self.clone();
        shielded.binding = self.binding.to_shielded_salted(salt);

        // Blind subject_key with secret salt
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_salted_subject_key_v1:");
        hasher.update(salt);
        hasher.update(self.subject_key);
        shielded.subject_key = hasher.finalize().into();

        // Blind statement_id (privacy-preserving nullifier) with secret salt
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_salted_statement_id_v1:");
        hasher.update(salt);
        hasher.update(self.statement_id);
        shielded.statement_id = hasher.finalize().into();

        shielded
    }

    /// Returns true if this statement's subject key and statement ID match the expected
    /// unblinded values when blinded with `salt`.
    pub fn verify_salted_blinding(
        &self,
        salt: &[u8; 32],
        unblinded_subject_key: &[u8; 32],
        unblinded_statement_id: &[u8; 32],
    ) -> bool {
        let mut h1 = Sha256::new();
        h1.update(b"mosoo_salted_subject_key_v1:");
        h1.update(salt);
        h1.update(unblinded_subject_key);
        let expected_subj: [u8; 32] = h1.finalize().into();

        let mut h2 = Sha256::new();
        h2.update(b"mosoo_salted_statement_id_v1:");
        h2.update(salt);
        h2.update(unblinded_statement_id);
        let expected_stmt: [u8; 32] = h2.finalize().into();

        self.subject_key == expected_subj && self.statement_id == expected_stmt
    }

    /// Converts this verified statement into a confidential shielded statement with a secret 256-bit blinding salt,
    /// blinding the verbose provenance binding, subject key, statement ID (nullifier), AND verified_value
    /// to provide value confidentiality in addition to address and event unlinkability.
    pub fn shield_confidential(&self, salt: &[u8; 32]) -> Self {
        let mut shielded = self.shield_with_salt(salt);

        // Blind verified_value with secret salt to prevent value leakage to public observers
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_salted_value_commitment_v1:");
        hasher.update(salt);
        hasher.update(self.verified_value);
        let val_commitment: [u8; 32] = hasher.finalize().into();

        shielded.binding = StatementBinding::Confidential {
            commitment: self.binding.compute_salted_commitment(salt),
            value_commitment: val_commitment,
        };
        shielded.verified_value = val_commitment;

        shielded
    }

    /// Verifies whether the blinded value commitment in this shielded statement corresponds
    /// to the given unblinded 32-byte value when opened with `salt`.
    pub fn verify_salted_value_commitment(
        &self,
        salt: &[u8; 32],
        unblinded_value: &[u8; 32],
    ) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(b"mosoo_salted_value_commitment_v1:");
        hasher.update(salt);
        hasher.update(unblinded_value);
        let expected: [u8; 32] = hasher.finalize().into();
        self.verified_value == expected
    }

    /// Returns true if the verified_value in this statement has been blinded.
    pub fn is_value_shielded(&self) -> bool {
        matches!(self.binding, StatementBinding::Confidential { .. })
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

impl Default for VerifiedStatement {
    fn default() -> Self {
        Self {
            chain_id: 1,
            genesis_validators_root: [0u8; 32],
            source_instance_id: [0u8; 32],
            source_instance_pda: [0u8; 32],
            attester_program_id: MOSOO_PROGRAM_ID,
            statement_id: [0u8; 32],
            predicate_holds: false,
            verified_value: [0u8; 32],
            subject_key: [0u8; 32],
            proof_type_tag: 0,
            binding: StatementBinding::default(),
        }
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
    /// Constructs a verified StatementAccount owned by `MOSOO_PROGRAM_ID` (test and harness only).
    /// In production, StatementAccount must be loaded via `try_from_runtime_account` or from authenticated AccountStore.
    #[cfg(any(test, feature = "test-harness"))]
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

pub use crate::verifier::{AttestStateArgs, GuestInstruction, InstructionOutput};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MosooError;

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

    #[test]
    fn test_bootstrap_admin_authority_one_time_and_registration() {
        let mut store = ProgramAccountStore::new();
        let admin = [0xabu8; 32];
        let attacker = [0x66u8; 32];

        // 1. Zero address rejected
        let res_zero = crate::verifier::handle_bootstrap_admin_authority(&mut store, [0u8; 32]);
        assert!(matches!(res_zero, Err(MosooError::InvalidBootstrap(_))));

        // 2. Initial bootstrap succeeds
        let res_ok = crate::verifier::handle_bootstrap_admin_authority(&mut store, admin);
        assert!(matches!(
            res_ok,
            Ok(crate::verifier::InstructionOutput::ConfigUpdated)
        ));

        // 3. Second bootstrap fails with AlreadyInitialized (strictly one-time)
        let res_replay = crate::verifier::handle_bootstrap_admin_authority(&mut store, attacker);
        assert!(matches!(
            res_replay,
            Err(MosooError::AlreadyInitialized { .. })
        ));

        // 4. Authorized checkpoint registration with newly bootstrapped admin succeeds
        let reg_ok = crate::verifier::handle_register_network_checkpoint_authenticated(
            &mut store,
            &admin,
            1,
            [0x11u8; 32],
            100,
        );
        assert!(reg_ok.is_ok());

        // 5. Unauthorized caller rejected
        let reg_unauth = crate::verifier::handle_register_network_checkpoint_authenticated(
            &mut store,
            &attacker,
            1,
            [0x22u8; 32],
            200,
        );
        assert!(matches!(
            reg_unauth,
            Err(MosooError::DomainSeparationFailed)
        ));
    }
}
