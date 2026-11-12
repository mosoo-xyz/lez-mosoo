//! Canonical RISC Zero outbound burn & LEZ state-transition journal helpers (RFP-022).
//!
//! Shared between the LEZ/RISC Zero proof producer (`mosoo-core` / guest witness verifier)
//! and Ethereum settlement (`contracts/MosooZkBurnVerifier.sol` + `contracts/MosooLocker.sol`).
//!
//! Every journal uses strict fixed-size big-endian 32-byte ABI words so that:
//! 1. `sha256(journal)` matches Solidity's native `sha256(journal)` precompile bit-for-bit.
//! 2. Zero dirty upper padding bits are permitted in `address` or `uint64` ABI slots, preventing
//!    canonical journal malleability across `sha256(journal)`.

use crate::error::MosooError;
use crate::types::{derive_shielded_burn_nullifier, verify_commitment_merkle_inclusion};
use sha2::{Digest, Sha256};

/// Depth of the shielded Merkle commitment tree (`[[u8; 32]; 20]`).
pub const OUTBOUND_MERKLE_DEPTH: usize = 20;

/// Exact byte length of `OutboundBurnJournal` ABI encoding (`9 * 32` bytes).
pub const OUTBOUND_BURN_JOURNAL_LEN: usize = 288;

/// Exact byte length of `LezStateTransitionJournal` ABI encoding (`7 * 32` bytes).
pub const STATE_TRANSITION_JOURNAL_LEN: usize = 224;

/// Domain prefix for outbound burn Merkle leaf commitments inside the LEZ burn tree.
const OUTBOUND_BURN_LEAF_DOMAIN: &[u8] = b"mosoo_outbound_burn_leaf_v1";

/// Public journal committed by an outbound burn zkVM receipt and decoded by
/// `MosooZkBurnVerifier.verifyOutboundBurn(bytes seal, bytes journal)`.
///
/// Intentionally omits `lez_owner`, `burn_nonce`, and `burn_secret` so Ethereum L1
/// never observes the burner's LEZ identity or sequential nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundBurnJournal {
    pub chain_id: u64,
    pub locker: [u8; 20],
    pub source_instance: [u8; 32],
    pub lez_state_root: [u8; 32],
    pub burn_nullifier: [u8; 32],
    /// `[0u8; 20]` for native ETH unlocks, or the ERC-20 contract address.
    pub asset_token: [u8; 20],
    pub recipient: [u8; 20],
    pub amount: u128,
    pub lez_slot: u64,
}

/// Public journal committed by an LEZ state-transition zkVM receipt and decoded by
/// `MosooZkBurnVerifier.advanceLezStateRootWithProof(bytes stateSeal, bytes stateJournal)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LezStateTransitionJournal {
    pub chain_id: u64,
    pub verifier: [u8; 20],
    pub source_instance: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub prev_slot: u64,
    pub new_slot: u64,
}

/// Private guest witness proving an unlinkable LEZ burn occurred under `lez_state_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundBurnWitness {
    pub chain_id: u64,
    pub locker: [u8; 20],
    pub source_instance: [u8; 32],
    pub lez_state_root: [u8; 32],
    pub lez_owner: [u8; 32],
    pub asset_token: [u8; 20],
    pub recipient: [u8; 20],
    pub amount: u128,
    pub burn_nonce: u64,
    pub lez_slot: u64,
    pub burn_secret: [u8; 32],
    pub leaf_index: u32,
    pub siblings: [[u8; 32]; OUTBOUND_MERKLE_DEPTH],
}

fn push_u64_word(out: &mut Vec<u8>, val: u64) {
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&val.to_be_bytes());
}

fn push_u128_word(out: &mut Vec<u8>, val: u128) {
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&val.to_be_bytes());
}

fn push_address_word(out: &mut Vec<u8>, addr: &[u8; 20]) {
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(addr);
}

fn read_word(data: &[u8], word_index: usize) -> &[u8] {
    let start = word_index * 32;
    &data[start..start + 32]
}

fn require_zero_prefix(word: &[u8], prefix_len: usize, field: &str) -> Result<(), MosooError> {
    if word[..prefix_len].iter().any(|&b| b != 0) {
        return Err(MosooError::Serialization(format!(
            "non-zero ABI padding in {field}"
        )));
    }
    Ok(())
}

fn decode_u64_word(word: &[u8], field: &str) -> Result<u64, MosooError> {
    require_zero_prefix(word, 24, field)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf))
}

fn decode_u128_word(word: &[u8], field: &str) -> Result<u128, MosooError> {
    require_zero_prefix(word, 16, field)?;
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..32]);
    Ok(u128::from_be_bytes(buf))
}

fn decode_address_word(word: &[u8], field: &str) -> Result<[u8; 20], MosooError> {
    require_zero_prefix(word, 12, field)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..32]);
    Ok(out)
}

fn decode_bytes32_word(word: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(word);
    out
}

impl OutboundBurnJournal {
    /// Validate non-zero domain and value invariants matching `MosooZkBurnVerifier.sol`.
    pub fn validate(&self) -> Result<(), MosooError> {
        if self.chain_id == 0 {
            return Err(MosooError::UnsupportedChain(0));
        }
        if self.locker == [0u8; 20] || self.recipient == [0u8; 20] {
            return Err(MosooError::DomainSeparationFailed);
        }
        if self.source_instance == [0u8; 32] {
            return Err(MosooError::UnauthenticatedSourceInstance);
        }
        if self.lez_state_root == [0u8; 32] || self.burn_nullifier == [0u8; 32] {
            return Err(MosooError::DomainSeparationFailed);
        }
        if self.amount == 0 || self.lez_slot == 0 {
            return Err(MosooError::Serialization(
                "outbound burn amount and lez_slot must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    /// Encode into exact 288-byte static Ethereum ABI calldata matching Solidity `abi.decode`.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OUTBOUND_BURN_JOURNAL_LEN);
        push_u64_word(&mut out, self.chain_id);
        push_address_word(&mut out, &self.locker);
        out.extend_from_slice(&self.source_instance);
        out.extend_from_slice(&self.lez_state_root);
        out.extend_from_slice(&self.burn_nullifier);
        push_address_word(&mut out, &self.asset_token);
        push_address_word(&mut out, &self.recipient);
        push_u128_word(&mut out, self.amount);
        push_u64_word(&mut out, self.lez_slot);
        out
    }

    /// Decode strict 288-byte canonical ABI journal, rejecting dirty padding bits.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self, MosooError> {
        if bytes.len() != OUTBOUND_BURN_JOURNAL_LEN {
            return Err(MosooError::Serialization(format!(
                "invalid OutboundBurnJournal length: expected {}, got {}",
                OUTBOUND_BURN_JOURNAL_LEN,
                bytes.len()
            )));
        }
        let journal = Self {
            chain_id: decode_u64_word(read_word(bytes, 0), "chain_id")?,
            locker: decode_address_word(read_word(bytes, 1), "locker")?,
            source_instance: decode_bytes32_word(read_word(bytes, 2)),
            lez_state_root: decode_bytes32_word(read_word(bytes, 3)),
            burn_nullifier: decode_bytes32_word(read_word(bytes, 4)),
            asset_token: decode_address_word(read_word(bytes, 5), "asset_token")?,
            recipient: decode_address_word(read_word(bytes, 6), "recipient")?,
            amount: decode_u128_word(read_word(bytes, 7), "amount")?,
            lez_slot: decode_u64_word(read_word(bytes, 8), "lez_slot")?,
        };
        journal.validate()?;
        Ok(journal)
    }

    /// Compute RISC Zero journal digest `sha256(abi_encode())` matching Solidity `sha256(journal)`.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.abi_encode()).into()
    }
}

impl LezStateTransitionJournal {
    /// Validate state-transition invariants matching `MosooZkBurnVerifier.advanceLezStateRootWithProof`.
    pub fn validate(&self) -> Result<(), MosooError> {
        if self.chain_id == 0 {
            return Err(MosooError::UnsupportedChain(0));
        }
        if self.verifier == [0u8; 20] {
            return Err(MosooError::DomainSeparationFailed);
        }
        if self.source_instance == [0u8; 32] {
            return Err(MosooError::UnauthenticatedSourceInstance);
        }
        if self.prev_state_root == [0u8; 32]
            || self.new_state_root == [0u8; 32]
            || self.new_state_root == self.prev_state_root
        {
            return Err(MosooError::DomainSeparationFailed);
        }
        if self.new_slot <= self.prev_slot {
            return Err(MosooError::StaleUpdate {
                update_slot: self.new_slot,
                current_slot: self.prev_slot,
            });
        }
        Ok(())
    }

    /// Encode into exact 224-byte static Ethereum ABI calldata matching Solidity `abi.decode`.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_TRANSITION_JOURNAL_LEN);
        push_u64_word(&mut out, self.chain_id);
        push_address_word(&mut out, &self.verifier);
        out.extend_from_slice(&self.source_instance);
        out.extend_from_slice(&self.prev_state_root);
        out.extend_from_slice(&self.new_state_root);
        push_u64_word(&mut out, self.prev_slot);
        push_u64_word(&mut out, self.new_slot);
        out
    }

    /// Decode strict 224-byte canonical ABI journal, rejecting dirty padding bits.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self, MosooError> {
        if bytes.len() != STATE_TRANSITION_JOURNAL_LEN {
            return Err(MosooError::Serialization(format!(
                "invalid LezStateTransitionJournal length: expected {}, got {}",
                STATE_TRANSITION_JOURNAL_LEN,
                bytes.len()
            )));
        }
        let journal = Self {
            chain_id: decode_u64_word(read_word(bytes, 0), "chain_id")?,
            verifier: decode_address_word(read_word(bytes, 1), "verifier")?,
            source_instance: decode_bytes32_word(read_word(bytes, 2)),
            prev_state_root: decode_bytes32_word(read_word(bytes, 3)),
            new_state_root: decode_bytes32_word(read_word(bytes, 4)),
            prev_slot: decode_u64_word(read_word(bytes, 5), "prev_slot")?,
            new_slot: decode_u64_word(read_word(bytes, 6), "new_slot")?,
        };
        journal.validate()?;
        Ok(journal)
    }

    /// Compute RISC Zero journal digest `sha256(abi_encode())` matching Solidity `sha256(stateJournal)`.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.abi_encode()).into()
    }
}

/// Computes the deterministic leaf commitment recorded inside LEZ's outbound burn Merkle tree:
/// `keccak256("mosoo_outbound_burn_leaf_v1" || chain_id || locker || source_instance || lez_owner || asset_token || recipient || amount || burn_nonce || lez_slot || burn_secret)`.
#[allow(clippy::too_many_arguments)]
pub fn derive_outbound_burn_leaf_commitment(
    chain_id: u64,
    locker: &[u8; 20],
    source_instance: &[u8; 32],
    lez_owner: &[u8; 32],
    asset_token: &[u8; 20],
    recipient: &[u8; 20],
    amount: u128,
    burn_nonce: u64,
    lez_slot: u64,
    burn_secret: &[u8; 32],
) -> [u8; 32] {
    let mut amount_be32 = [0u8; 32];
    amount_be32[16..32].copy_from_slice(&amount.to_be_bytes());
    let mut buf = Vec::with_capacity(
        OUTBOUND_BURN_LEAF_DOMAIN.len() + 8 + 20 + 32 + 32 + 20 + 20 + 32 + 8 + 8 + 32,
    );
    buf.extend_from_slice(OUTBOUND_BURN_LEAF_DOMAIN);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(locker);
    buf.extend_from_slice(source_instance);
    buf.extend_from_slice(lez_owner);
    buf.extend_from_slice(asset_token);
    buf.extend_from_slice(recipient);
    buf.extend_from_slice(&amount_be32);
    buf.extend_from_slice(&burn_nonce.to_be_bytes());
    buf.extend_from_slice(&lez_slot.to_be_bytes());
    buf.extend_from_slice(burn_secret);
    alloy_primitives::keccak256(&buf).0
}

/// Verifies a private outbound burn witness inside a RISC Zero guest/prover context and emits the
/// privacy-preserving public `OutboundBurnJournal` (with `lez_owner`, `burn_nonce`, and `burn_secret` withheld).
pub fn verify_outbound_burn_witness(
    witness: &OutboundBurnWitness,
) -> Result<OutboundBurnJournal, MosooError> {
    if witness.burn_secret == [0u8; 32] || witness.lez_owner == [0u8; 32] {
        return Err(MosooError::DomainSeparationFailed);
    }
    if witness.burn_nonce == 0 {
        return Err(MosooError::Serialization(
            "burn_nonce must be >= 1".to_string(),
        ));
    }

    let mut amount_be32 = [0u8; 32];
    amount_be32[16..32].copy_from_slice(&witness.amount.to_be_bytes());
    let burn_nullifier = derive_shielded_burn_nullifier(
        witness.chain_id,
        &witness.source_instance,
        &witness.asset_token,
        &amount_be32,
        &witness.burn_secret,
    );

    let leaf = derive_outbound_burn_leaf_commitment(
        witness.chain_id,
        &witness.locker,
        &witness.source_instance,
        &witness.lez_owner,
        &witness.asset_token,
        &witness.recipient,
        witness.amount,
        witness.burn_nonce,
        witness.lez_slot,
        &witness.burn_secret,
    );

    if !verify_commitment_merkle_inclusion(
        &leaf,
        witness.leaf_index,
        &witness.siblings,
        &witness.lez_state_root,
    ) {
        return Err(MosooError::InvalidTrieProof);
    }

    let journal = OutboundBurnJournal {
        chain_id: witness.chain_id,
        locker: witness.locker,
        source_instance: witness.source_instance,
        lez_state_root: witness.lez_state_root,
        burn_nullifier,
        asset_token: witness.asset_token,
        recipient: witness.recipient,
        amount: witness.amount,
        lez_slot: witness.lez_slot,
    };
    journal.validate()?;
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut packed = [0u8; 15 + 32 + 32];
        packed[..15].copy_from_slice(b"mosoo_merkle_v1");
        packed[15..47].copy_from_slice(left);
        packed[47..79].copy_from_slice(right);
        alloy_primitives::keccak256(packed).0
    }

    fn compute_root_from_leaf(
        leaf: [u8; 32],
        leaf_index: u32,
        siblings: &[[u8; 32]; OUTBOUND_MERKLE_DEPTH],
    ) -> [u8; 32] {
        let mut idx = leaf_index;
        let mut cur = leaf;
        for sib in siblings.iter() {
            cur = if idx.is_multiple_of(2) {
                hash_pair(&cur, sib)
            } else {
                hash_pair(sib, &cur)
            };
            idx /= 2;
        }
        cur
    }

    #[test]
    fn outbound_burn_journal_abi_roundtrip_and_padding_guards() {
        let j = OutboundBurnJournal {
            chain_id: 11155111,
            locker: [0x11; 20],
            source_instance: [0x22; 32],
            lez_state_root: [0x33; 32],
            burn_nullifier: [0x44; 32],
            asset_token: [0x55; 20],
            recipient: [0x66; 20],
            amount: 100_000_000_000_000_000u128,
            lez_slot: 81_648,
        };
        let encoded = j.abi_encode();
        assert_eq!(encoded.len(), OUTBOUND_BURN_JOURNAL_LEN);
        assert_eq!(OutboundBurnJournal::abi_decode(&encoded).unwrap(), j);
        assert_eq!(j.digest(), <[u8; 32]>::from(Sha256::digest(&encoded)));

        // Reject wrong length
        assert!(OutboundBurnJournal::abi_decode(&encoded[..287]).is_err());

        // Reject dirty upper padding bits in `locker` (word 1, byte 32..44) and `lez_slot` (word 8, byte 256..280)
        let mut dirty_locker = encoded.clone();
        dirty_locker[32] = 0x01;
        assert!(OutboundBurnJournal::abi_decode(&dirty_locker).is_err());

        let mut dirty_slot = encoded;
        dirty_slot[256] = 0xff;
        assert!(OutboundBurnJournal::abi_decode(&dirty_slot).is_err());
    }

    #[test]
    fn state_transition_journal_abi_roundtrip_and_monotonicity() {
        let s = LezStateTransitionJournal {
            chain_id: 11155111,
            verifier: [0xaa; 20],
            source_instance: [0xbb; 32],
            prev_state_root: [0x01; 32],
            new_state_root: [0x02; 32],
            prev_slot: 100,
            new_slot: 164,
        };
        let encoded = s.abi_encode();
        assert_eq!(encoded.len(), STATE_TRANSITION_JOURNAL_LEN);
        assert_eq!(LezStateTransitionJournal::abi_decode(&encoded).unwrap(), s);

        let mut stale = s.clone();
        stale.new_slot = stale.prev_slot;
        assert!(stale.validate().is_err());

        let mut unchanged_root = s;
        unchanged_root.new_state_root = unchanged_root.prev_state_root;
        assert!(unchanged_root.validate().is_err());
    }

    #[test]
    fn verify_outbound_burn_witness_derives_shielded_journal_and_rejects_forgery() {
        let locker = [0x9au8; 20];
        let source_instance = [0x7bu8; 32];
        let lez_owner = [0x12u8; 32];
        let recipient = [0x34u8; 20];
        let burn_secret = [0x56u8; 32];
        let amount = 10_000_000_000_000_000u128; // 0.01 ETH
        let burn_nonce = 7u64;
        let lez_slot = 81_648u64;
        let leaf_index = 5u32;
        let mut siblings = [[0u8; 32]; OUTBOUND_MERKLE_DEPTH];
        siblings[0] = [0xaa; 32];
        siblings[1] = [0xbb; 32];

        let leaf = derive_outbound_burn_leaf_commitment(
            11155111,
            &locker,
            &source_instance,
            &lez_owner,
            &[0u8; 20],
            &recipient,
            amount,
            burn_nonce,
            lez_slot,
            &burn_secret,
        );
        let lez_state_root = compute_root_from_leaf(leaf, leaf_index, &siblings);

        let witness = OutboundBurnWitness {
            chain_id: 11155111,
            locker,
            source_instance,
            lez_state_root,
            lez_owner,
            asset_token: [0u8; 20],
            recipient,
            amount,
            burn_nonce,
            lez_slot,
            burn_secret,
            leaf_index,
            siblings,
        };

        let journal = verify_outbound_burn_witness(&witness).unwrap();
        assert_eq!(journal.recipient, recipient);
        assert_eq!(journal.amount, amount);
        assert_eq!(journal.lez_state_root, lez_state_root);

        // Journal contains NO lez_owner or burn_secret bytes
        let encoded = journal.abi_encode();
        assert!(!encoded
            .windows(32)
            .any(|w| w == lez_owner || w == burn_secret));

        // Tampering any witness field (amount / recipient / sibling) fails inclusion check
        let mut forged = witness.clone();
        forged.recipient[0] ^= 0xff;
        assert!(verify_outbound_burn_witness(&forged).is_err());

        let mut wrong_secret = witness;
        wrong_secret.burn_secret[31] ^= 0x01;
        assert!(verify_outbound_burn_witness(&wrong_secret).is_err());
    }
}
