//! BLS12-381 cryptographic helpers used inside the RISC0 guest and off-chain host.
//!
//! All functions here use the `blst` crate, which provides optimized
//! pairing and curve operations (assembly-accelerated on host, portable C in zkVM).

use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;

use crate::error::MosooError;
use crate::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, LightClientUpdate, NetworkConfig, SyncAggregate,
    SyncCommittee,
};

/// Domain separation tag for Ethereum BLS signatures (EIP-2335 / BLS spec).
pub const ETH_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Canonical byte length of 512-validator sync-committee participation bitfield (512 / 8 = 64 bytes).
pub const SYNC_COMMITTEE_BITS_BYTES: usize = 64;

/// Canonical byte length of BLS12-381 G2 compressed signature.
pub const SYNC_COMMITTEE_SIGNATURE_BYTES: usize = 96;

/// Strictly validate the length of sync aggregate bitvector and signature to prevent
/// quorum bypass or malformed serialization attacks.
pub fn verify_sync_aggregate_lengths(bits: &[u8], sig: &[u8]) -> Result<(), MosooError> {
    if bits.len() != SYNC_COMMITTEE_BITS_BYTES {
        return Err(MosooError::InvalidSyncCommitteeBitsLength {
            actual: bits.len(),
            expected: SYNC_COMMITTEE_BITS_BYTES,
        });
    }
    if sig.len() != SYNC_COMMITTEE_SIGNATURE_BYTES {
        return Err(MosooError::InvalidSyncCommitteeSignatureLength {
            actual: sig.len(),
            expected: SYNC_COMMITTEE_SIGNATURE_BYTES,
        });
    }
    Ok(())
}

/// Count the number of set bits in the sync-committee participation bitvector.
pub fn count_participation(bits: &[u8]) -> usize {
    bits.iter().map(|b| b.count_ones() as usize).sum()
}

/// Return `true` if the validator at `index` participated.
pub fn validator_participated(bits: &[u8], index: usize) -> bool {
    let byte = bits.get(index / 8).copied().unwrap_or(0);
    byte & (1 << (index % 8)) != 0
}

/// Aggregate the pubkeys of only the validators that participated in the
/// sync-committee signature.
///
/// Returns the compressed G1 aggregate pubkey (48 bytes).
pub fn aggregate_participating_pubkeys(
    committee: &SyncCommittee,
    participation: &[u8],
) -> Result<[u8; 48], MosooError> {
    let mut participating: Vec<PublicKey> = Vec::new();

    for (i, pk_vec) in committee.pubkeys.iter().enumerate() {
        if validator_participated(participation, i) {
            if pk_vec.len() != 48 {
                return Err(MosooError::InvalidPublicKey(format!(
                    "validator {i}: pubkey is {} bytes, expected 48",
                    pk_vec.len()
                )));
            }
            let pk = PublicKey::from_bytes(pk_vec)
                .map_err(|e| MosooError::InvalidPublicKey(format!("validator {i}: {e:?}")))?;
            participating.push(pk);
        }
    }

    if participating.is_empty() {
        return Err(MosooError::InsufficientParticipation {
            actual: 0,
            required: 342, // ceil(512 * 2/3)
        });
    }

    // Aggregate all participating pubkeys into a single G1 point.
    let refs: Vec<&PublicKey> = participating.iter().collect();
    let agg =
        AggregatePublicKey::aggregate(&refs, false).map_err(|_| MosooError::AggregationFailed)?;

    Ok(agg.to_public_key().to_bytes())
}

/// Compute the BLS signing root for a beacon block header with optional network configuration.
///
/// signing_root = sha256(hash_tree_root(header) || domain)
pub fn compute_signing_root_with_config(
    header: &BeaconBlockHeader,
    chain_id: u64,
    signature_slot: u64,
    network_config: Option<&NetworkConfig>,
) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};

    let header_root = hash_tree_root_beacon_header(header);
    let domain =
        compute_sync_committee_domain_with_config(chain_id, signature_slot, network_config);

    let mut hasher = Sha256::new();
    hasher.update(header_root);
    hasher.update(domain);
    Ok(hasher.finalize().into())
}

/// Compute the BLS signing root for a beacon block header.
///
/// signing_root = sha256(hash_tree_root(header) || domain)
pub fn compute_signing_root(
    header: &BeaconBlockHeader,
    chain_id: u64,
    signature_slot: u64,
) -> Result<[u8; 32], MosooError> {
    compute_signing_root_with_config(header, chain_id, signature_slot, None)
}

/// Compute the BLS domain for DOMAIN_SYNC_COMMITTEE with optional network configuration.
pub fn compute_sync_committee_domain_with_config(
    chain_id: u64,
    slot: u64,
    network_config: Option<&NetworkConfig>,
) -> [u8; 32] {
    // DOMAIN_SYNC_COMMITTEE = 0x07000000
    let domain_type: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
    let (fork, gvr) = if let Some(config) = network_config {
        let gvr = if config.genesis_validators_root != [0u8; 32] {
            config.genesis_validators_root
        } else {
            genesis_validators_root(chain_id)
        };
        let fork_kind = ethereum_fork(chain_id, slot);
        let fork_v = match fork_kind {
            EthereumFork::Gloas if config.gloas_fork_version != [0u8; 4] => {
                config.gloas_fork_version
            }
            EthereumFork::Fulu if config.fulu_fork_version != [0u8; 4] => config.fulu_fork_version,
            EthereumFork::Electra if config.electra_fork_version != [0u8; 4] => {
                config.electra_fork_version
            }
            EthereumFork::Deneb if config.deneb_fork_version != [0u8; 4] => {
                config.deneb_fork_version
            }
            EthereumFork::Capella if config.capella_fork_version != [0u8; 4] => {
                config.capella_fork_version
            }
            EthereumFork::Bellatrix if config.bellatrix_fork_version != [0u8; 4] => {
                config.bellatrix_fork_version
            }
            EthereumFork::Altair if config.altair_fork_version != [0u8; 4] => {
                config.altair_fork_version
            }
            _ => fork_version(chain_id, slot),
        };
        (fork_v, gvr)
    } else {
        (
            fork_version(chain_id, slot),
            genesis_validators_root(chain_id),
        )
    };
    compute_domain(domain_type, fork, gvr)
}

/// Compute the BLS domain for DOMAIN_SYNC_COMMITTEE on the given chain.
pub fn compute_sync_committee_domain(chain_id: u64, slot: u64) -> [u8; 32] {
    compute_sync_committee_domain_with_config(chain_id, slot, None)
}

/// Compute 32-byte BLS domain per Ethereum consensus specs: domain_type + fork_data_root[:28].
pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut fork_data_root = Sha256::new();
    fork_data_root.update(fork_version);
    fork_data_root.update([0u8; 28]); // zero-pad to 32 bytes
    fork_data_root.update(genesis_validators_root);
    let fork_data_hash: [u8; 32] = fork_data_root.finalize().into();

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_hash[..28]);
    domain
}

/// Ethereum fork version metadata per official consensus specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkSchedule {
    pub name: &'static str,
    pub epoch: u64,
    pub slot: u64,
    pub version: [u8; 4],
}

/// Returns the Ethereum consensus fork version for a given chain ID and slot.
///
/// Fully supports Ethereum Mainnet (1), Sepolia (11155111), and Holesky (17000)
/// across all active and scheduled forks including Deneb, Electra, and Fulu.
pub fn fork_version(chain_id: u64, slot: u64) -> [u8; 4] {
    match chain_id {
        // Ethereum Mainnet (Chain ID 1)
        1 => {
            // FULU_FORK_EPOCH = 411392 (slot 13,164,544)
            if slot >= 13_164_544 {
                [0x06, 0x00, 0x00, 0x00] // FULU_FORK_VERSION
                                         // ELECTRA_FORK_EPOCH = 364032 (slot 11,649,024)
            } else if slot >= 11_649_024 {
                [0x05, 0x00, 0x00, 0x00] // ELECTRA_FORK_VERSION
                                         // DENEB_FORK_EPOCH = 269568 (slot 8,626,176)
            } else if slot >= 8_626_176 {
                [0x04, 0x00, 0x00, 0x00] // DENEB_FORK_VERSION
                                         // CAPELLA_FORK_EPOCH = 194048 (slot 6,209,536)
            } else if slot >= 6_209_536 {
                [0x03, 0x00, 0x00, 0x00] // CAPELLA_FORK_VERSION
                                         // BELLATRIX_FORK_EPOCH = 146176 (slot 4,677,632)
            } else if slot >= 4_677_632 {
                [0x02, 0x00, 0x00, 0x00] // BELLATRIX_FORK_VERSION
                                         // ALTAIR_FORK_EPOCH = 74240 (slot 2,375,680)
            } else if slot >= 2_375_680 {
                [0x01, 0x00, 0x00, 0x00] // ALTAIR_FORK_VERSION
            } else {
                [0x00, 0x00, 0x00, 0x00] // GENESIS_FORK_VERSION
            }
        }
        // Sepolia Testnet (Chain ID 11155111)
        11_155_111 => {
            // SEPOLIA_GLOAS_FORK_EPOCH = 353024 (slot 11,296,768, official EF Glamsterdam activation Oct 6, 2026)
            if slot >= 11_296_768 {
                [0x90, 0x00, 0x00, 0x77] // SEPOLIA_GLOAS_FORK_VERSION
            } else if slot >= 6_189_056 {
                [0x90, 0x00, 0x00, 0x75] // SEPOLIA_ELECTRA_FORK_VERSION
            } else if slot >= 4_243_456 {
                [0x90, 0x00, 0x00, 0x74] // SEPOLIA_DENEB_FORK_VERSION
            } else if slot >= 112_640 {
                [0x90, 0x00, 0x00, 0x73] // SEPOLIA_CAPELLA_FORK_VERSION
            } else {
                [0x90, 0x00, 0x00, 0x70] // SEPOLIA_ALTAIR_FORK_VERSION
            }
        }
        // Hoodi Testnet (Chain ID 560048) - Gloas upgrade postponed on Oct 22, 2026; remaining on Fulu until official replacement schedule
        560_048 => {
            [0x10, 0x00, 0x09, 0x00] // HOODI_FULU_FORK_VERSION
        }
        // Holesky Testnet (Chain ID 17000 - Deprecated)
        17_000 => {
            if slot >= 2_000_000 {
                [0x06, 0x01, 0x70, 0x00] // HOLESKY_FULU_FORK_VERSION
            } else if slot >= 1_000_000 {
                [0x05, 0x01, 0x70, 0x00] // HOLESKY_ELECTRA_FORK_VERSION
            } else {
                [0x04, 0x01, 0x70, 0x00] // HOLESKY_DENEB_FORK_VERSION
            }
        }
        _ => [0u8; 4],
    }
}

/// Ethereum consensus fork identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EthereumFork {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

/// Generalized indices defined by Ethereum consensus specifications.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ALTAIR: u64 = 54;
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 86;
pub const CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS: u64 = 2945;

pub const NEXT_SYNC_COMMITTEE_GINDEX_ALTAIR: u64 = 55;
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 87;
pub const NEXT_SYNC_COMMITTEE_GINDEX_GLOAS: u64 = 2946;

pub const FINALIZED_ROOT_GINDEX_ALTAIR: u64 = 105;
pub const FINALIZED_ROOT_GINDEX_ELECTRA: u64 = 169;
pub const FINALIZED_ROOT_GINDEX_GLOAS: u64 = 735;

pub const EXECUTION_PAYLOAD_GINDEX_ALTAIR: u64 = 25;
pub const EXECUTION_BLOCK_HASH_GINDEX_GLOAS: u64 = 2856;

pub const BLOCK_ROOTS_GINDEX_PREFIX_ALTAIR: u64 = 37;
pub const BLOCK_ROOTS_GINDEX_PREFIX_ELECTRA: u64 = 69;

/// Returns the active Ethereum consensus fork for a given network and slot.
pub fn ethereum_fork(chain_id: u64, slot: u64) -> EthereumFork {
    match chain_id {
        1 => {
            if slot >= 13_164_544 {
                EthereumFork::Fulu
            } else if slot >= 11_649_024 {
                EthereumFork::Electra
            } else if slot >= 8_626_176 {
                EthereumFork::Deneb
            } else if slot >= 6_209_536 {
                EthereumFork::Capella
            } else if slot >= 4_677_632 {
                EthereumFork::Bellatrix
            } else if slot >= 2_375_680 {
                EthereumFork::Altair
            } else {
                EthereumFork::Phase0
            }
        }
        11_155_111 => {
            if slot >= 11_296_768 {
                EthereumFork::Gloas
            } else if slot >= 6_189_056 {
                EthereumFork::Electra
            } else if slot >= 4_243_456 {
                EthereumFork::Deneb
            } else if slot >= 112_640 {
                EthereumFork::Capella
            } else {
                EthereumFork::Altair
            }
        }
        // Hoodi Testnet (Chain ID 560048) - Gloas postponed, remaining on Fulu
        560_048 => EthereumFork::Fulu,
        17_000 => {
            if slot >= 2_000_000 {
                EthereumFork::Fulu
            } else if slot >= 1_000_000 {
                EthereumFork::Electra
            } else {
                EthereumFork::Deneb
            }
        }
        _ => EthereumFork::Altair,
    }
}

/// Returns the SSZ generalized index for `current_sync_committee` in `BeaconState`.
pub fn current_sync_committee_gindex(chain_id: u64, slot: u64) -> u64 {
    match ethereum_fork(chain_id, slot) {
        EthereumFork::Gloas => CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
        EthereumFork::Electra | EthereumFork::Fulu => CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        _ => CURRENT_SYNC_COMMITTEE_GINDEX_ALTAIR,
    }
}

/// Returns the SSZ generalized index for `next_sync_committee` in `BeaconState`.
pub fn next_sync_committee_gindex(chain_id: u64, slot: u64) -> u64 {
    match ethereum_fork(chain_id, slot) {
        EthereumFork::Gloas => NEXT_SYNC_COMMITTEE_GINDEX_GLOAS,
        EthereumFork::Electra | EthereumFork::Fulu => NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        _ => NEXT_SYNC_COMMITTEE_GINDEX_ALTAIR,
    }
}

/// Returns the SSZ generalized index for `finalized_checkpoint.root` in `BeaconState`.
pub fn finalized_root_gindex(chain_id: u64, slot: u64) -> u64 {
    match ethereum_fork(chain_id, slot) {
        EthereumFork::Gloas => FINALIZED_ROOT_GINDEX_GLOAS,
        EthereumFork::Electra | EthereumFork::Fulu => FINALIZED_ROOT_GINDEX_ELECTRA,
        _ => FINALIZED_ROOT_GINDEX_ALTAIR,
    }
}

/// Returns the SSZ generalized index for execution proof in `BeaconBlockBody`.
pub fn execution_proof_gindex(chain_id: u64, slot: u64) -> u64 {
    match ethereum_fork(chain_id, slot) {
        EthereumFork::Gloas => EXECUTION_BLOCK_HASH_GINDEX_GLOAS,
        _ => EXECUTION_PAYLOAD_GINDEX_ALTAIR,
    }
}

/// Returns the SSZ generalized index for `block_roots[slot % 8192]` in `BeaconState`.
pub fn historical_block_roots_gindex(chain_id: u64, state_slot: u64, target_slot: u64) -> u64 {
    let prefix = match ethereum_fork(chain_id, state_slot) {
        EthereumFork::Gloas | EthereumFork::Electra | EthereumFork::Fulu => {
            BLOCK_ROOTS_GINDEX_PREFIX_ELECTRA
        }
        _ => BLOCK_ROOTS_GINDEX_PREFIX_ALTAIR,
    };
    (prefix << 13) | (target_slot % 8192)
}

/// Returns true if the chain ID is an officially supported Ethereum network.
pub fn is_supported_chain(chain_id: u64) -> bool {
    matches!(chain_id, 1 | 11_155_111 | 560_048 | 17_000)
}

/// Returns true if the chain ID is supported or provided with a valid explicit NetworkConfig.
/// Enables network-agnostic operation for arbitrary consensus chains per RFP-021 Functionality #14.
pub fn is_supported_chain_or_configured(
    chain_id: u64,
    config: Option<&crate::types::NetworkConfig>,
) -> bool {
    if is_supported_chain(chain_id) {
        return true;
    }
    if let Some(cfg) = config {
        return cfg.chain_id == chain_id && cfg.genesis_validators_root != [0u8; 32];
    }
    false
}

/// Returns genesis_validators_root for a given chain.
pub fn genesis_validators_root(chain_id: u64) -> [u8; 32] {
    match chain_id {
        1 => hex_to_bytes32("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
        11_155_111 => {
            hex_to_bytes32("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
        }
        560_048 => {
            hex_to_bytes32("b9525c317f2272e5052309f451f28b7fae13a0c5c3619574ad1c4f4b9f27113e")
        }
        17_000 => {
            hex_to_bytes32("9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
        }
        _ => [0u8; 32],
    }
}

/// Legacy internal helper for (fork_version, genesis_validators_root).
pub fn chain_params(chain_id: u64, slot: u64) -> ([u8; 4], [u8; 32]) {
    (
        fork_version(chain_id, slot),
        genesis_validators_root(chain_id),
    )
}

/// SHA256 / SSZ hash-tree-root of a BeaconBlockHeader.
pub fn hash_tree_root_beacon_header(header: &BeaconBlockHeader) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let u64_leaf = |v: u64| {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&v.to_le_bytes());
        buf
    };

    let leaves: [[u8; 32]; 5] = [
        u64_leaf(header.slot),
        u64_leaf(header.proposer_index),
        header.parent_root,
        header.state_root,
        header.body_root,
    ];

    let mut nodes = leaves.to_vec();
    while nodes.len() < 8 {
        nodes.push([0u8; 32]);
    }

    let mut layer = nodes;
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
    }
    layer[0]
}

/// SSZ hash_tree_root of a 48-byte compressed BLS public key (ByteVector[48]).
///
/// Per the SSZ specification:
/// Chunk 0: bytes 0..32
/// Chunk 1: bytes 32..48 right-padded with 16 zero bytes to 32 bytes
/// Root = sha256(chunk0 || chunk1)
pub fn hash_tree_root_bls_pubkey(pubkey: &[u8]) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};
    if pubkey.len() != 48 {
        return Err(MosooError::InvalidPublicKey(format!(
            "pubkey is {} bytes, expected 48",
            pubkey.len()
        )));
    }
    let mut chunk1 = [0u8; 32];
    chunk1[..16].copy_from_slice(&pubkey[32..48]);

    let mut hasher = Sha256::new();
    hasher.update(&pubkey[..32]);
    hasher.update(chunk1);
    Ok(hasher.finalize().into())
}

/// Spec-compliant SSZ hash-tree-root of a SyncCommittee (Vector[BLSPubkey, 512] + aggregate_pubkey).
pub fn hash_tree_root_sync_committee(committee: &SyncCommittee) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};
    if committee.pubkeys.len() != 512 {
        return Err(MosooError::Internal(
            "sync committee must have exactly 512 pubkeys".into(),
        ));
    }

    let mut leaves = Vec::with_capacity(512);
    for pk in &committee.pubkeys {
        leaves.push(hash_tree_root_bls_pubkey(pk)?);
    }

    // Binary Merkleization over 512 leaves (depth 9)
    let mut layer = leaves;
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
    }
    let pubkeys_root = layer[0];

    // Aggregate pubkey root (ByteVector[48])
    let agg_root = hash_tree_root_bls_pubkey(&committee.aggregate_pubkey)?;

    let mut h = Sha256::new();
    h.update(pubkeys_root);
    h.update(agg_root);
    Ok(h.finalize().into())
}

/// Canonical SSZ ByteList[32] hash-tree-root for extra_data.
/// In Ethereum SSZ, ByteList[max_len] packs data into 32-byte chunks, pads to max_len chunks,
/// and mixes in length: `hash(chunk_root || uint256(len))`.
pub fn hash_tree_root_extra_data(extra_data: &[u8]) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};
    if extra_data.len() > 32 {
        return Err(MosooError::InvalidExtraDataLength {
            actual: extra_data.len(),
            max: 32,
        });
    }
    let mut chunk = [0u8; 32];
    chunk[..extra_data.len()].copy_from_slice(extra_data);

    let mut len_leaf = [0u8; 32];
    len_leaf[..8].copy_from_slice(&(extra_data.len() as u64).to_le_bytes());

    let mut hasher = Sha256::new();
    hasher.update(chunk);
    hasher.update(len_leaf);
    Ok(hasher.finalize().into())
}

/// Canonical SSZ hash-tree-root of logs_bloom (ByteVector[256]).
/// Enforces exact 256 bytes (8 chunks of 32 bytes merkleized into depth 3 root).
pub fn hash_tree_root_logs_bloom(logs_bloom: &[u8]) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};
    if logs_bloom.len() != 256 {
        return Err(MosooError::InvalidLogsBloomLength {
            actual: logs_bloom.len(),
            expected: 256,
        });
    }

    let mut bloom_chunks: Vec<[u8; 32]> = Vec::with_capacity(8);
    for i in 0..8 {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&logs_bloom[i * 32..(i + 1) * 32]);
        bloom_chunks.push(chunk);
    }
    let mut bloom_layer = bloom_chunks;
    while bloom_layer.len() > 1 {
        bloom_layer = bloom_layer
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
    }
    Ok(bloom_layer[0])
}

/// Compute the SSZ hash-tree-root of an ExecutionPayloadHeader.
/// Fork-aware:
/// - Bellatrix (14 fields) / Capella (15 fields): Merkleized as 16 leaves (depth 4)
/// - Deneb / Electra / Gloas (17 fields with blob_gas_used, excess_blob_gas): Merkleized as 32 leaves (depth 5)
pub fn hash_tree_root_execution_payload_header(
    header: &ExecutionPayloadHeader,
) -> Result<[u8; 32], MosooError> {
    use sha2::{Digest, Sha256};

    let u64_leaf = |v: u64| {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&v.to_le_bytes());
        buf
    };

    let mut fee_recipient_padded = [0u8; 32];
    fee_recipient_padded[..20].copy_from_slice(&header.fee_recipient);

    let logs_bloom_root = hash_tree_root_logs_bloom(&header.logs_bloom)?;
    let extra_data_root = hash_tree_root_extra_data(&header.extra_data)?;

    let is_deneb_or_later = header.blob_gas_used.is_some() || header.excess_blob_gas.is_some();

    if is_deneb_or_later {
        // Deneb / Electra / Gloas container: 17 fields -> next power of 2 is 32 leaves (depth 5)
        let mut leaves: Vec<[u8; 32]> = vec![[0u8; 32]; 32];
        leaves[0] = header.parent_hash;
        leaves[1] = fee_recipient_padded;
        leaves[2] = header.state_root;
        leaves[3] = header.receipts_root;
        leaves[4] = logs_bloom_root;
        leaves[5] = header.prev_randao;
        leaves[6] = u64_leaf(header.block_number);
        leaves[7] = u64_leaf(header.gas_limit);
        leaves[8] = u64_leaf(header.gas_used);
        leaves[9] = u64_leaf(header.timestamp);
        leaves[10] = extra_data_root;
        leaves[11] = header.base_fee_per_gas;
        leaves[12] = header.block_hash;
        leaves[13] = header.transactions_root;
        leaves[14] = header.withdrawals_root.unwrap_or([0u8; 32]);
        leaves[15] = u64_leaf(header.blob_gas_used.unwrap_or(0));
        leaves[16] = u64_leaf(header.excess_blob_gas.unwrap_or(0));
        // leaves[17..31] are zero-padded

        let mut layer = leaves;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha256::new();
                    h.update(pair[0]);
                    h.update(pair[1]);
                    h.finalize().into()
                })
                .collect();
        }
        Ok(layer[0])
    } else {
        // Bellatrix / Capella container: 14-15 fields -> 16 leaves (depth 4)
        let mut leaves: Vec<[u8; 32]> = vec![[0u8; 32]; 16];
        leaves[0] = header.parent_hash;
        leaves[1] = fee_recipient_padded;
        leaves[2] = header.state_root;
        leaves[3] = header.receipts_root;
        leaves[4] = logs_bloom_root;
        leaves[5] = header.prev_randao;
        leaves[6] = u64_leaf(header.block_number);
        leaves[7] = u64_leaf(header.gas_limit);
        leaves[8] = u64_leaf(header.gas_used);
        leaves[9] = u64_leaf(header.timestamp);
        leaves[10] = extra_data_root;
        leaves[11] = header.base_fee_per_gas;
        leaves[12] = header.block_hash;
        leaves[13] = header.transactions_root;
        leaves[14] = header.withdrawals_root.unwrap_or([0u8; 32]);
        // leaves[15] is zero-padded

        let mut layer = leaves;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha256::new();
                    h.update(pair[0]);
                    h.update(pair[1]);
                    h.finalize().into()
                })
                .collect();
        }
        Ok(layer[0])
    }
}

/// Walk a Merkle proof branch from `leaf` up to the root using an SSZ generalized index.
pub fn compute_branch_root(leaf: [u8; 32], branch: &[[u8; 32]], gindex: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut node = leaf;
    let mut idx = gindex;

    for sibling in branch {
        let mut h = Sha256::new();
        if idx.is_multiple_of(2) {
            h.update(node);
            h.update(sibling);
        } else {
            h.update(sibling);
            h.update(node);
        }
        node = h.finalize().into();
        idx /= 2;
    }
    node
}

/// Walk a Merkle proof branch with strict depth validation against the generalized index.
/// Fails if the branch length does not equal floor(log2(gindex)).
pub fn compute_branch_root_checked(
    leaf: [u8; 32],
    branch: &[[u8; 32]],
    gindex: u64,
) -> Result<[u8; 32], MosooError> {
    if gindex == 0 {
        return Err(MosooError::Internal("gindex cannot be 0".into()));
    }
    let expected_depth = (63 - gindex.leading_zeros()) as usize;
    if branch.len() != expected_depth {
        return Err(MosooError::InvalidProofBranchDepth {
            actual: branch.len(),
            expected: expected_depth,
        });
    }
    Ok(compute_branch_root(leaf, branch, gindex))
}

/// Compute a deterministic 32-byte digest of a light-client update to cryptographically
/// bind transactions across the Begin, Miller, and Finish stages.
pub fn compute_update_digest(update: &LightClientUpdate) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"MOSOO_UPDATE_DIGEST_V1:");
    h.update(update.attested_header.slot.to_le_bytes());
    h.update(hash_tree_root_beacon_header(&update.attested_header));
    h.update(update.finalized_header.slot.to_le_bytes());
    h.update(hash_tree_root_beacon_header(&update.finalized_header));
    h.update(&update.sync_aggregate.sync_committee_bits);
    h.update(&update.sync_aggregate.sync_committee_signature);
    h.update(update.signature_slot.to_le_bytes());
    h.finalize().into()
}

/// Compute hash_to_G2(msg) using blst and serialize into compressed 96 bytes.
pub fn blst_hash_to_g2(msg: &[u8]) -> [u8; 96] {
    let mut p = blst::blst_p2::default();
    unsafe {
        blst::blst_hash_to_g2(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            ETH_BLS_DST.as_ptr(),
            ETH_BLS_DST.len(),
            core::ptr::null(),
            0,
        );
        let mut out = [0u8; 96];
        blst::blst_p2_compress(out.as_mut_ptr(), &p);
        out
    }
}

/// Compute two Miller loops for BLS verification:
/// ML1 = e(G1, sig)
/// ML2 = e(agg_pk, msg_g2)
///
/// Returns 1152 bytes containing ML1 (576 bytes) and ML2 (576 bytes) serialized.
pub fn blst_two_miller_loops(
    sig_bytes: &[u8],
    agg_pk_bytes: &[u8],
    msg_g2_bytes: &[u8],
) -> Result<[u8; 1152], MosooError> {
    if sig_bytes.len() != 96 {
        return Err(MosooError::InvalidSignature);
    }
    if agg_pk_bytes.len() != 48 {
        return Err(MosooError::InvalidPublicKey(format!(
            "agg_pk is {} bytes, expected 48",
            agg_pk_bytes.len()
        )));
    }
    if msg_g2_bytes.len() != 96 {
        return Err(MosooError::Internal(format!(
            "msg_g2 is {} bytes, expected 96",
            msg_g2_bytes.len()
        )));
    }

    let mut sig_aff = blst::blst_p2_affine::default();
    let err = unsafe { blst::blst_p2_uncompress(&mut sig_aff, sig_bytes.as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(MosooError::InvalidSignature);
    }

    let mut pk_aff = blst::blst_p1_affine::default();
    let err = unsafe { blst::blst_p1_uncompress(&mut pk_aff, agg_pk_bytes.as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(MosooError::InvalidPublicKey(format!("{err:?}")));
    }

    let mut msg_aff = blst::blst_p2_affine::default();
    let err = unsafe { blst::blst_p2_uncompress(&mut msg_aff, msg_g2_bytes.as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(MosooError::Internal(
            "failed to uncompress msg_g2 point".into(),
        ));
    }

    let mut ml1 = blst::blst_fp12::default();
    let mut ml2 = blst::blst_fp12::default();

    unsafe {
        let g1 = blst::blst_p1_affine_generator();
        blst::blst_miller_loop(&mut ml1, &sig_aff, g1);
        blst::blst_miller_loop(&mut ml2, &msg_aff, &pk_aff);
    }

    let mut out = [0u8; 1152];
    unsafe {
        let p1 = &ml1 as *const _ as *const u8;
        let p2 = &ml2 as *const _ as *const u8;
        core::ptr::copy_nonoverlapping(p1, out.as_mut_ptr(), 576);
        core::ptr::copy_nonoverlapping(p2, out.as_mut_ptr().add(576), 576);
    }
    Ok(out)
}

/// Perform final exponentiation and check whether e(G1, sig) == e(agg_pk, msg_g2).
pub fn blst_final_exp_and_verify(miller_result: &[u8]) -> Result<bool, MosooError> {
    if miller_result.len() != 1152 {
        return Err(MosooError::Internal(format!(
            "miller_result must be 1152 bytes, got {}",
            miller_result.len()
        )));
    }

    let mut ml1 = blst::blst_fp12::default();
    let mut ml2 = blst::blst_fp12::default();

    unsafe {
        let dst1 = &mut ml1 as *mut _ as *mut u8;
        let dst2 = &mut ml2 as *mut _ as *mut u8;
        core::ptr::copy_nonoverlapping(miller_result.as_ptr(), dst1, 576);
        core::ptr::copy_nonoverlapping(miller_result.as_ptr().add(576), dst2, 576);

        let valid = blst::blst_fp12_finalverify(&ml1, &ml2);
        Ok(valid)
    }
}

/// Verify a complete sync-committee signature in one call with optional network configuration.
pub fn verify_sync_committee_signature_with_config(
    committee: &SyncCommittee,
    aggregate: &SyncAggregate,
    header: &BeaconBlockHeader,
    chain_id: u64,
    signature_slot: u64,
    network_config: Option<&NetworkConfig>,
) -> Result<(), MosooError> {
    let participation = count_participation(&aggregate.sync_committee_bits);
    let threshold = (512usize * 2).div_ceil(3); // 342 validators (2/3 quorum)
    if participation < threshold {
        return Err(MosooError::InsufficientParticipation {
            actual: participation,
            required: threshold,
        });
    }
    let signing_root =
        compute_signing_root_with_config(header, chain_id, signature_slot, network_config)?;
    let agg_pubkey_bytes =
        aggregate_participating_pubkeys(committee, &aggregate.sync_committee_bits)?;
    let agg_pubkey = PublicKey::from_bytes(&agg_pubkey_bytes)
        .map_err(|e| MosooError::InvalidPublicKey(format!("{e:?}")))?;
    let sig = Signature::from_bytes(aggregate.sync_committee_signature.as_slice())
        .map_err(|_| MosooError::InvalidSignature)?;
    let result = sig.verify(true, &signing_root, ETH_BLS_DST, &[], &agg_pubkey, true);
    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(MosooError::InvalidSignature);
    }

    Ok(())
}

/// Verify a complete sync-committee signature in one call.
pub fn verify_sync_committee_signature(
    committee: &SyncCommittee,
    aggregate: &SyncAggregate,
    header: &BeaconBlockHeader,
    chain_id: u64,
    signature_slot: u64,
) -> Result<(), MosooError> {
    verify_sync_committee_signature_with_config(
        committee,
        aggregate,
        header,
        chain_id,
        signature_slot,
        None,
    )
}

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex constant");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    #[test]
    fn test_pairing_split_begin_miller_finish() {
        let ikm = [99u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        let msg = b"ethereum beacon block header signing root";
        let dst = ETH_BLS_DST;
        let sig = sk.sign(msg, dst, &[]);

        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Step 1: Hash to G2 (BeginUpdate)
        let msg_g2 = blst_hash_to_g2(msg);
        assert_eq!(msg_g2.len(), 96);

        // Step 2: Miller loops (MillerUpdate)
        let miller_bytes = blst_two_miller_loops(&sig_bytes, &pk_bytes, &msg_g2).unwrap();
        assert_eq!(miller_bytes.len(), 1152);

        // Step 3: Final exponentiation (FinishUpdate)
        let is_valid = blst_final_exp_and_verify(&miller_bytes).unwrap();
        assert!(
            is_valid,
            "Valid signature MUST verify via split Miller + FinalExp"
        );

        // Tampered signature MUST fail
        let bad_sig = sk.sign(b"corrupted message", dst, &[]);
        let bad_miller = blst_two_miller_loops(&bad_sig.to_bytes(), &pk_bytes, &msg_g2).unwrap();
        let is_bad_valid = blst_final_exp_and_verify(&bad_miller).unwrap();
        assert!(!is_bad_valid, "Tampered signature MUST fail verification");
    }

    #[test]
    fn test_execution_payload_header_branch_verification() {
        use sha2::{Digest, Sha256};

        let payload_header = ExecutionPayloadHeader {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: vec![0x55; 256],
            prev_randao: [0x66; 32],
            block_number: 19_500_000,
            gas_limit: 30_000_000,
            gas_used: 12_000_000,
            timestamp: 1_710_000_000,
            extra_data: vec![0xaa, 0xbb],
            base_fee_per_gas: [0x77; 32],
            block_hash: [0x88; 32],
            transactions_root: [0x99; 32],
            withdrawals_root: Some([0xaa; 32]),
            blob_gas_used: None,
            excess_blob_gas: None,
        };

        let payload_root = hash_tree_root_execution_payload_header(&payload_header).unwrap();

        // Simulate BeaconBlockBody with 16 fields where execution_payload is field index 9
        // Generalized index = 16 + 9 = 25
        let mut body_leaves = vec![[0u8; 32]; 16];
        body_leaves[9] = payload_root;

        // Build the Merkle tree for BeaconBlockBody to obtain the genuine branch siblings
        let mut layers = Vec::new();
        layers.push(body_leaves.clone());
        let mut current = body_leaves;
        while current.len() > 1 {
            let next: Vec<[u8; 32]> = current
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha256::new();
                    h.update(pair[0]);
                    h.update(pair[1]);
                    h.finalize().into()
                })
                .collect();
            layers.push(next.clone());
            current = next;
        }
        let body_root = layers.last().unwrap()[0];

        // Extract branch for index 25 (depth 4)
        let mut branch = Vec::new();
        let mut idx = 9usize;
        for layer in layers.iter().take(layers.len() - 1) {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            branch.push(layer[sibling_idx]);
            idx /= 2;
        }

        // Verify branch
        let computed = compute_branch_root_checked(payload_root, &branch, 25).unwrap();
        assert_eq!(
            computed, body_root,
            "Execution payload branch MUST resolve to body_root"
        );

        // Tampered payload state root MUST fail
        let mut tampered = payload_header.clone();
        tampered.state_root[0] ^= 0xff;
        let tampered_root = hash_tree_root_execution_payload_header(&tampered).unwrap();
        let tampered_computed = compute_branch_root(tampered_root, &branch, 25);
        assert_ne!(
            tampered_computed, body_root,
            "Tampered state root MUST NOT verify"
        );
    }

    #[test]
    fn test_deneb_execution_payload_header_32_leaves() {
        let deneb_header = ExecutionPayloadHeader {
            parent_hash: [0x01; 32],
            fee_recipient: [0x02; 20],
            state_root: [0x03; 32],
            receipts_root: [0x04; 32],
            logs_bloom: vec![0x00; 256],
            prev_randao: [0x05; 32],
            block_number: 19_426_587,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_710_338_135,
            extra_data: b"DenebUpgradeCanonical".to_vec(),
            base_fee_per_gas: [0x06; 32],
            block_hash: [0x07; 32],
            transactions_root: [0x08; 32],
            withdrawals_root: Some([0x09; 32]),
            blob_gas_used: Some(393_216),
            excess_blob_gas: Some(786_432),
        };

        let root = hash_tree_root_execution_payload_header(&deneb_header).unwrap();
        assert_ne!(root, [0u8; 32]);

        // Tampering with blob_gas_used must change root
        let mut tampered = deneb_header.clone();
        tampered.blob_gas_used = Some(524_288);
        let tampered_root = hash_tree_root_execution_payload_header(&tampered).unwrap();
        assert_ne!(root, tampered_root);
    }

    #[test]
    fn test_sync_committee_bits_strict_64_bytes_enforcement() {
        let valid_64_bytes = vec![0xff; 64];
        let valid_96_sig = vec![0xaa; 96];
        assert!(verify_sync_aggregate_lengths(&valid_64_bytes, &valid_96_sig).is_ok());

        // 63 bytes (underflow) MUST be rejected
        let short_bits = vec![0xff; 63];
        let err = verify_sync_aggregate_lengths(&short_bits, &valid_96_sig).unwrap_err();
        assert!(matches!(
            err,
            MosooError::InvalidSyncCommitteeBitsLength {
                actual: 63,
                expected: 64
            }
        ));

        // 65 bytes (attacker extra byte with fake quorum bit) MUST be rejected
        let long_bits = vec![0xff; 65];
        let err = verify_sync_aggregate_lengths(&long_bits, &valid_96_sig).unwrap_err();
        assert!(matches!(
            err,
            MosooError::InvalidSyncCommitteeBitsLength {
                actual: 65,
                expected: 64
            }
        ));

        // 95 bytes signature MUST be rejected
        let short_sig = vec![0xaa; 95];
        let err = verify_sync_aggregate_lengths(&valid_64_bytes, &short_sig).unwrap_err();
        assert!(matches!(
            err,
            MosooError::InvalidSyncCommitteeSignatureLength {
                actual: 95,
                expected: 96
            }
        ));
    }

    #[test]
    fn test_branch_depth_strict_validation() {
        let leaf = [0x11; 32];
        let branch_5 = vec![[0x22; 32]; 5]; // correct for gindex 54 or 55 (depth 5)
        assert!(compute_branch_root_checked(leaf, &branch_5, 54).is_ok());

        // Corrupted branch with depth 4 for gindex 54 MUST be rejected
        let branch_4 = vec![[0x22; 32]; 4];
        let err = compute_branch_root_checked(leaf, &branch_4, 54).unwrap_err();
        assert!(matches!(
            err,
            MosooError::InvalidProofBranchDepth {
                actual: 4,
                expected: 5
            }
        ));
    }

    #[test]
    fn test_sync_committee_ssz_merkleization_512() {
        // Construct dummy committee of 512 pubkeys (each 48 bytes)
        let pubkeys = vec![vec![0x12u8; 48]; 512];
        let aggregate_pubkey = vec![0x34u8; 48];
        let committee = SyncCommittee {
            pubkeys,
            aggregate_pubkey,
        };

        let root = hash_tree_root_sync_committee(&committee).unwrap();
        assert_ne!(root, [0u8; 32], "SyncCommittee root must not be zero");

        // Modifying any single pubkey must change the root
        let mut tampered = committee.clone();
        tampered.pubkeys[255][0] ^= 0xff;
        let tampered_root = hash_tree_root_sync_committee(&tampered).unwrap();
        assert_ne!(
            root, tampered_root,
            "Tampered pubkey MUST change sync committee root"
        );
    }

    #[test]
    fn test_mainnet_fork_boundaries_electra_and_fulu() {
        // Capella -> Deneb boundary
        assert_eq!(fork_version(1, 8_626_175), [0x03, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 8_626_176), [0x04, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 8_626_177), [0x04, 0x00, 0x00, 0x00]);

        // Deneb -> Electra boundary (slot 11,649,024)
        assert_eq!(fork_version(1, 11_649_023), [0x04, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 11_649_024), [0x05, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 11_649_025), [0x05, 0x00, 0x00, 0x00]);

        // Electra -> Fulu boundary (slot 13,164,544)
        assert_eq!(fork_version(1, 13_164_543), [0x05, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 13_164_544), [0x06, 0x00, 0x00, 0x00]);
        assert_eq!(fork_version(1, 13_164_545), [0x06, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_period_1884_canonical_slot_and_fulu_domain() {
        // Period 1884 start slot = 1884 * 8192 = 15,433,728 (Epoch 482,304)
        let period_1884_start = 1884 * 8192;
        assert_eq!(period_1884_start, 15_433_728);
        assert_eq!(fork_version(1, period_1884_start), [0x06, 0x00, 0x00, 0x00]);

        // Period 1884 update slot = 15,433,760
        let period_1884_update = 15_433_760;
        assert_eq!(
            fork_version(1, period_1884_update),
            [0x06, 0x00, 0x00, 0x00]
        );

        // Verify domain computation for Period 1884 under Fulu rules
        let domain = compute_sync_committee_domain(1, period_1884_update);
        assert_eq!(&domain[..4], &[0x07, 0x00, 0x00, 0x00]); // DOMAIN_SYNC_COMMITTEE
        assert_ne!(domain, [0u8; 32]);
    }

    #[test]
    fn test_sepolia_fork_boundaries_electra_and_fulu() {
        // Sepolia Capella -> Deneb boundary (slot 4,243,456)
        assert_eq!(
            fork_version(11_155_111, 4_243_455),
            [0x90, 0x00, 0x00, 0x73]
        );
        assert_eq!(
            fork_version(11_155_111, 4_243_456),
            [0x90, 0x00, 0x00, 0x74]
        );
        assert_eq!(
            fork_version(11_155_111, 4_243_457),
            [0x90, 0x00, 0x00, 0x74]
        );

        // Sepolia Deneb -> Electra boundary (slot 6,189,056)
        assert_eq!(
            fork_version(11_155_111, 6_189_055),
            [0x90, 0x00, 0x00, 0x74]
        );
        assert_eq!(
            fork_version(11_155_111, 6_189_056),
            [0x90, 0x00, 0x00, 0x75]
        );
        assert_eq!(
            fork_version(11_155_111, 6_189_057),
            [0x90, 0x00, 0x00, 0x75]
        );

        // Sepolia Electra -> Gloas boundary (slot 11,296,768, official EF Glamsterdam activation Oct 6, 2026)
        assert_eq!(
            fork_version(11_155_111, 11_296_767),
            [0x90, 0x00, 0x00, 0x75]
        );
        assert_eq!(
            fork_version(11_155_111, 11_296_768),
            [0x90, 0x00, 0x00, 0x77]
        );
        assert_eq!(
            fork_version(11_155_111, 11_296_769),
            [0x90, 0x00, 0x00, 0x77]
        );

        // Hoodi testnet (chain_id: 560048) remaining on Fulu (Gloas postponed on Oct 22, 2026)
        assert_eq!(fork_version(560_048, 786_431), [0x10, 0x00, 0x09, 0x00]);
        assert_eq!(fork_version(560_048, 786_432), [0x10, 0x00, 0x09, 0x00]);
        assert_eq!(fork_version(560_048, 1_000_000), [0x10, 0x00, 0x09, 0x00]);
    }

    #[test]
    fn test_domain_derivation_across_forks() {
        let domain_deneb = compute_sync_committee_domain(1, 9_000_000);
        let domain_electra = compute_sync_committee_domain(1, 12_000_000);
        let domain_fulu = compute_sync_committee_domain(1, 14_000_000);

        // Domain type 0x07000000 is preserved in top 4 bytes
        assert_eq!(&domain_deneb[..4], &[0x07, 0x00, 0x00, 0x00]);
        assert_eq!(&domain_electra[..4], &[0x07, 0x00, 0x00, 0x00]);
        assert_eq!(&domain_fulu[..4], &[0x07, 0x00, 0x00, 0x00]);

        // Domains across fork upgrades MUST NOT collide
        assert_ne!(domain_deneb, domain_electra);
        assert_ne!(domain_electra, domain_fulu);
        assert_ne!(domain_deneb, domain_fulu);
    }
}
