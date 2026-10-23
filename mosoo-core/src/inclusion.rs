//! Ethereum Merkle-Patricia Trie inclusion proof verification.
//!
//! Verifies `eth_getProof` outputs and transaction receipt event logs against
//! a finalized `HeaderRecord`.
//! The header record MUST come from the Mosoo on-chain store — callers
//! cannot inject an arbitrary execution state root or receipts root.
//!
//! ### Proof types supported
//! - **Account proof** — native ETH balance (`eth_getProof`).
//! - **Storage proof** — ERC-20 storage slot value (`eth_getProof`).
//! - **Receipt-log proof** — MPT receipt inclusion & event log verification (EIP-2718 typed & legacy).

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::proof::verify_proof;
use nybbles::Nibbles;
use serde::{Deserialize, Serialize};

use crate::error::MosooError;
use crate::types::HeaderRecord;

/// The verified value returned after a successful inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedValue {
    /// Native ETH balance of an account, in wei.
    EthBalance(U256),
    /// Raw 32-byte value stored at a contract storage slot.
    StorageValue([u8; 32]),
    /// Event log payload data or topic (e.g. transfer amount or raw payload bytes).
    LogData(Vec<u8>),
}

impl VerifiedValue {
    /// Return the value as a big-endian 32-byte array for predicate evaluation.
    ///
    /// For log data ≤ 32 bytes (standard EVM words like uint256 transfer amounts),
    /// pads left with zeros.
    /// For variable-length event data > 32 bytes (dynamic strings, byte arrays, complex structs),
    /// computes a domain-separated Keccak-256 hash `keccak256("MOSOO_EVENT_PAYLOAD_HASH:" || data)`
    /// to guarantee collision-free and truncation-free predicate binding (P1 Security).
    pub fn as_bytes32(&self) -> [u8; 32] {
        match self {
            VerifiedValue::EthBalance(v) => v.to_be_bytes(),
            VerifiedValue::StorageValue(v) => *v,
            VerifiedValue::LogData(v) => {
                if v.len() <= 32 {
                    let mut out = [0u8; 32];
                    out[32 - v.len()..].copy_from_slice(v);
                    out
                } else {
                    let mut prefixed = Vec::with_capacity(25 + v.len());
                    prefixed.extend_from_slice(b"MOSOO_EVENT_PAYLOAD_HASH:");
                    prefixed.extend_from_slice(v);
                    keccak256(&prefixed).0
                }
            }
        }
    }
}

/// What the caller wants to prove against the finalized execution header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofTarget {
    /// Prove the native ETH balance of `address`.
    AccountBalance { address: Address },
    /// Prove the value stored at `slot` in `contract`'s storage.
    StorageSlot { contract: Address, slot: B256 },
    /// Prove an event log emitted at `log_index` by transaction `tx_index`.
    ReceiptLog {
        tx_index: u64,
        log_index: usize,
        emitter: Address,
        topic0: B256,
    },
    /// Prove an ERC-20 Transfer event: Transfer(address from, address to, uint256 amount)
    /// emitted by `token_contract`.
    Erc20Transfer {
        tx_index: u64,
        log_index: usize,
        token_contract: Address,
        sender: Address,
        recipient: [u8; 32],
    },
    /// Prove a Native ETH deposit to a bridge vault contract:
    /// Deposit(address sender, bytes32 recipient, uint256 amount) or Deposit(address sender, address recipient, uint256 amount).
    NativeEthDeposit {
        tx_index: u64,
        log_index: usize,
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
    },
}

/// Standalone proof payload for verifying an Ethereum transaction receipt and its emitted event logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLogProof {
    /// Transaction index within the block.
    pub tx_index: u64,
    /// Zero-based index of the log within the transaction's receipt.
    pub log_index: usize,
    /// Optional expected emitter contract address.
    pub expected_emitter: Option<Address>,
    /// Optional expected topic0 (e.g. keccak256("Transfer(address,address,uint256)")).
    pub expected_topic0: Option<B256>,
    /// RLP-encoded Merkle-Patricia trie nodes proving receipt existence against `header.receipts_root`.
    pub receipt_proof: Vec<Bytes>,
    /// The expected RLP-encoded receipt at the leaf of the trie.
    pub receipt_rlp: Vec<u8>,
}

/// A cryptographically verified event log extracted from an authenticated receipt trie proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedLog {
    /// The contract that emitted the event.
    pub emitter: Address,
    /// Event topics (topic0 is event signature hash, topic1..topic3 are indexed arguments).
    pub topics: Vec<B256>,
    /// Non-indexed event data bytes.
    pub data: Vec<u8>,
    /// Transaction index within the block.
    pub tx_index: u64,
    /// Index of this log within the transaction receipt.
    pub log_index: usize,
}

/// Full proof payload — mirrors `eth_getProof` JSON output and receipt inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    pub target: ProofTarget,
    /// RLP-encoded Merkle-Patricia nodes for the account trie path.
    pub account_proof: Vec<Bytes>,
    /// RLP-encoded Merkle-Patricia nodes for the storage trie path.
    /// Only required for `StorageSlot` proofs.
    pub storage_proof: Option<Vec<Bytes>>,
    /// RLP-encoded Merkle-Patricia nodes for the receipts trie path.
    /// Only required for `ReceiptLog` proofs.
    pub receipt_proof: Option<Vec<Bytes>>,
    /// The expected RLP-encoded account value at the leaf of the account proof.
    pub account_value: Option<Vec<u8>>,
    /// The expected RLP-encoded value at the storage leaf.
    pub storage_value: Option<Vec<u8>>,
    /// The expected RLP-encoded receipt at the leaf of the receipts trie.
    pub receipt_value: Option<Vec<u8>>,
}

/// Verify a state or receipt inclusion proof against a finalized `HeaderRecord`.
///
/// **Security:** `header` must be an authenticated `HeaderRecord` from Mosoo.
/// Callers cannot supply arbitrary execution state roots or receipt roots.
pub fn verify_state_proof(
    proof: &StateProof,
    header: &HeaderRecord,
) -> Result<VerifiedValue, MosooError> {
    let state_root = B256::from(header.execution_state_root);

    match &proof.target {
        ProofTarget::AccountBalance { address } => {
            verify_account_balance(proof, state_root, *address)
        }
        ProofTarget::StorageSlot { contract, slot } => {
            verify_storage_slot(proof, state_root, *contract, *slot)
        }
        ProofTarget::ReceiptLog {
            tx_index,
            log_index,
            emitter,
            topic0,
        } => {
            let r_proof = ReceiptLogProof {
                tx_index: *tx_index,
                log_index: *log_index,
                expected_emitter: Some(*emitter),
                expected_topic0: Some(*topic0),
                receipt_proof: proof.receipt_proof.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_proof required for ReceiptLog proof".into())
                })?,
                receipt_rlp: proof.receipt_value.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_value required for ReceiptLog proof".into())
                })?,
            };
            let verified_log = verify_receipt_log_proof(&r_proof, header)?;
            if !verified_log.data.is_empty() {
                Ok(VerifiedValue::LogData(verified_log.data))
            } else if let Some(t) = verified_log.topics.first() {
                Ok(VerifiedValue::StorageValue(t.0))
            } else {
                Ok(VerifiedValue::StorageValue([0u8; 32]))
            }
        }
        ProofTarget::Erc20Transfer {
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            let erc20_transfer_topic0 = B256::from(alloy_primitives::keccak256(
                b"Transfer(address,address,uint256)",
            ));
            let r_proof = ReceiptLogProof {
                tx_index: *tx_index,
                log_index: *log_index,
                expected_emitter: Some(*token_contract),
                expected_topic0: Some(erc20_transfer_topic0),
                receipt_proof: proof.receipt_proof.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_proof required for Erc20Transfer proof".into())
                })?,
                receipt_rlp: proof.receipt_value.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_value required for Erc20Transfer proof".into())
                })?,
            };
            let verified_log = verify_receipt_log_proof(&r_proof, header)?;
            if verified_log.topics.len() < 3 {
                return Err(MosooError::RlpDecodeFailed(
                    "ERC-20 Transfer log must have at least 3 topics (sig, from, to)".into(),
                ));
            }
            let from_topic = verified_log.topics[1];
            if &from_topic.0[12..32] != sender.as_slice() {
                return Err(MosooError::Internal(
                    "sender address mismatch in Transfer log".into(),
                ));
            }
            let to_topic = verified_log.topics[2];
            let matches_recipient = if to_topic.0 == *recipient {
                true
            } else if recipient[0..12] == [0u8; 12] {
                to_topic.0[12..32] == recipient[12..32]
            } else if to_topic.0[0..12] == [0u8; 12] {
                to_topic.0[12..32] == recipient[12..32] || to_topic.0[12..32] == recipient[0..20]
            } else {
                false
            };
            if !matches_recipient {
                return Err(MosooError::Internal(
                    "recipient mismatch in Transfer log".into(),
                ));
            }
            if verified_log.data.is_empty() {
                return Err(MosooError::Internal(
                    "missing transfer amount in log data".into(),
                ));
            }
            Ok(VerifiedValue::LogData(verified_log.data))
        }
        ProofTarget::NativeEthDeposit {
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        } => {
            let deposit_topic0_bytes32 = B256::from(alloy_primitives::keccak256(
                b"Deposit(address,bytes32,uint256)",
            ));
            let deposit_topic0_addr = B256::from(alloy_primitives::keccak256(
                b"Deposit(address,address,uint256)",
            ));
            let r_proof = ReceiptLogProof {
                tx_index: *tx_index,
                log_index: *log_index,
                expected_emitter: Some(*deposit_contract),
                expected_topic0: None,
                receipt_proof: proof.receipt_proof.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_proof required for NativeEthDeposit proof".into())
                })?,
                receipt_rlp: proof.receipt_value.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_value required for NativeEthDeposit proof".into())
                })?,
            };
            let verified_log = verify_receipt_log_proof(&r_proof, header)?;
            if verified_log.topics.is_empty() {
                return Err(MosooError::Internal("deposit log missing topics".into()));
            }
            let sig = verified_log.topics[0];
            if sig != deposit_topic0_bytes32 && sig != deposit_topic0_addr {
                return Err(MosooError::EventTopicMismatch {
                    index: 0,
                    expected: format!("{deposit_topic0_bytes32:?}"),
                    actual: format!("{sig:?}"),
                });
            }
            if verified_log.topics.len() >= 2 {
                let from_topic = verified_log.topics[1];
                if &from_topic.0[12..32] != sender.as_slice() {
                    return Err(MosooError::Internal(
                        "sender address mismatch in Deposit log".into(),
                    ));
                }
            }
            if verified_log.topics.len() >= 3 {
                let to_topic = verified_log.topics[2];
                let matches_recipient = if to_topic.0 == *recipient {
                    true
                } else if recipient[0..12] == [0u8; 12] {
                    to_topic.0[12..32] == recipient[12..32]
                } else if to_topic.0[0..12] == [0u8; 12] {
                    to_topic.0[12..32] == recipient[12..32]
                        || to_topic.0[12..32] == recipient[0..20]
                } else {
                    false
                };
                if !matches_recipient {
                    return Err(MosooError::Internal(
                        "recipient mismatch in Deposit log".into(),
                    ));
                }
            }
            if verified_log.data.is_empty() {
                return Err(MosooError::Internal(
                    "missing deposit amount in log data".into(),
                ));
            }
            Ok(VerifiedValue::LogData(verified_log.data))
        }
    }
}

/// Verify a receipt log proof against a finalized `HeaderRecord`.
pub fn verify_receipt_log_proof(
    proof: &ReceiptLogProof,
    header: &HeaderRecord,
) -> Result<VerifiedLog, MosooError> {
    let receipts_root = B256::from(header.receipts_root);
    if receipts_root == B256::ZERO {
        return Err(MosooError::InvalidTrieProof);
    }

    // In Ethereum receipt tries, the key is RLP(tx_index)
    let key_bytes = alloy_rlp::encode(proof.tx_index);
    let nibbles = Nibbles::unpack(&key_bytes);

    verify_proof(
        receipts_root,
        nibbles,
        Some(proof.receipt_rlp.clone()),
        &proof.receipt_proof,
    )
    .map_err(|_| MosooError::InvalidTrieProof)?;

    decode_and_validate_receipt(
        &proof.receipt_rlp,
        proof.tx_index,
        proof.log_index,
        proof.expected_emitter,
        proof.expected_topic0,
    )
}

/// Decode an Ethereum receipt and validate the emitted log at `target_log_index`.
pub fn decode_and_validate_receipt(
    receipt_bytes: &[u8],
    tx_index: u64,
    target_log_index: usize,
    expected_emitter: Option<Address>,
    expected_topic0: Option<B256>,
) -> Result<VerifiedLog, MosooError> {
    if receipt_bytes.is_empty() {
        return Err(MosooError::RlpDecodeFailed("empty receipt bytes".into()));
    }

    // Handle EIP-2718 typed transaction receipt envelope.
    // Typed receipts (0x01, 0x02, 0x03) prefix the RLP payload with the 1-byte type flag.
    // Legacy receipts begin with RLP list prefix (>= 0xc0).
    let rlp_payload = if receipt_bytes[0] < 0x80 {
        &receipt_bytes[1..]
    } else {
        receipt_bytes
    };

    // Parse receipt fields: [status_or_state_root, cumulative_gas_used, logs_bloom, logs]
    let fields = rlp_decode_list_items(rlp_payload)?;
    if fields.len() < 4 {
        return Err(MosooError::RlpDecodeFailed(format!(
            "receipt must have at least 4 items, got {}",
            fields.len()
        )));
    }

    // Validate transaction execution status (EIP-658). Reverted transactions (status = 0)
    // MUST NOT be attested.
    let status_raw = rlp_strip_prefix(fields[0]);
    if status_raw.is_empty() || status_raw == [0u8] {
        return Err(MosooError::Internal(
            "transaction reverted (status = 0); events from failed transactions cannot be attested"
                .into(),
        ));
    }

    // Parse logs list: [log_0, log_1, ...]
    let raw_logs = rlp_decode_list_items(fields[3])?;
    if target_log_index >= raw_logs.len() {
        return Err(MosooError::LogIndexOutOfBounds {
            log_index: target_log_index,
            total_logs: raw_logs.len(),
        });
    }

    // Parse target log: [address, [topic0, topic1, ...], data]
    let log_fields = rlp_decode_list_items(raw_logs[target_log_index])?;
    if log_fields.len() < 3 {
        return Err(MosooError::RlpDecodeFailed(format!(
            "log must have 3 items (address, topics, data), got {}",
            log_fields.len()
        )));
    }

    let emitter_bytes = rlp_strip_prefix(log_fields[0]);
    if emitter_bytes.len() != 20 {
        return Err(MosooError::RlpDecodeFailed(format!(
            "emitter address is {} bytes, expected 20",
            emitter_bytes.len()
        )));
    }
    let emitter = Address::from_slice(emitter_bytes);

    if let Some(expected) = expected_emitter {
        if emitter != expected {
            return Err(MosooError::EventEmitterMismatch {
                expected: format!("{expected:?}"),
                actual: format!("{emitter:?}"),
            });
        }
    }

    let topic_items = rlp_decode_list_items(log_fields[1])?;
    let mut topics = Vec::with_capacity(topic_items.len());
    for item in topic_items {
        let topic_bytes = rlp_strip_prefix(item);
        if topic_bytes.len() != 32 {
            return Err(MosooError::RlpDecodeFailed(format!(
                "topic is {} bytes, expected 32",
                topic_bytes.len()
            )));
        }
        topics.push(B256::from_slice(topic_bytes));
    }

    if let Some(expected_t0) = expected_topic0 {
        let actual_t0 = topics.first().copied();
        if actual_t0 != Some(expected_t0) {
            return Err(MosooError::EventTopicMismatch {
                index: 0,
                expected: format!("{expected_t0:?}"),
                actual: actual_t0
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| "none".into()),
            });
        }
    }

    let data = rlp_strip_prefix(log_fields[2]).to_vec();

    Ok(VerifiedLog {
        emitter,
        topics,
        data,
        tx_index,
        log_index: target_log_index,
    })
}

/// Parse an RLP list into the byte slices of its child items.
pub fn rlp_decode_list_items(buf: &[u8]) -> Result<Vec<&[u8]>, MosooError> {
    if buf.is_empty() {
        return Err(MosooError::RlpDecodeFailed("empty buffer".into()));
    }
    let first = buf[0];
    let payload = if first >= 0xf8 {
        let ll = (first - 0xf7) as usize;
        if buf.len() < 1 + ll {
            return Err(MosooError::RlpDecodeFailed("truncated list header".into()));
        }
        let len = decode_be_usize(&buf[1..1 + ll]);
        if buf.len() < 1 + ll + len {
            return Err(MosooError::RlpDecodeFailed("truncated list payload".into()));
        }
        &buf[1 + ll..1 + ll + len]
    } else if first >= 0xc0 {
        let len = (first - 0xc0) as usize;
        if buf.len() < 1 + len {
            return Err(MosooError::RlpDecodeFailed("truncated list payload".into()));
        }
        &buf[1..1 + len]
    } else {
        return Err(MosooError::RlpDecodeFailed(format!(
            "expected RLP list prefix, got 0x{first:02x}"
        )));
    };

    let mut items = Vec::new();
    let mut remaining = payload;
    while !remaining.is_empty() {
        let (item, rest) = rlp_next_item(remaining)?;
        items.push(item);
        remaining = rest;
    }
    Ok(items)
}

/// Verify an account's existence and return its ETH balance.
fn verify_account_balance(
    proof: &StateProof,
    state_root: B256,
    address: Address,
) -> Result<VerifiedValue, MosooError> {
    let account_key_hash = keccak256(address.as_slice());
    let nibbles = Nibbles::unpack(account_key_hash.as_slice());

    let expected_value = proof
        .account_value
        .clone()
        .ok_or_else(|| MosooError::Internal("account_value required for balance proof".into()))?;

    verify_proof(
        state_root,
        nibbles,
        Some(expected_value.clone()),
        &proof.account_proof,
    )
    .map_err(|_| MosooError::InvalidTrieProof)?;

    let balance = decode_account_balance(&expected_value)?;
    Ok(VerifiedValue::EthBalance(balance))
}

/// Verify a contract storage slot's value.
fn verify_storage_slot(
    proof: &StateProof,
    state_root: B256,
    contract: Address,
    slot: B256,
) -> Result<VerifiedValue, MosooError> {
    // Resolve account storage root from state trie.
    let account_key_hash = keccak256(contract.as_slice());
    let account_nibbles = Nibbles::unpack(account_key_hash.as_slice());

    let account_value = proof
        .account_value
        .clone()
        .ok_or_else(|| MosooError::Internal("account_value required for storage proof".into()))?;

    verify_proof(
        state_root,
        account_nibbles,
        Some(account_value.clone()),
        &proof.account_proof,
    )
    .map_err(|_| MosooError::InvalidTrieProof)?;

    let storage_root = decode_account_storage_root(&account_value)?;

    // Verify requested storage slot against contract storage trie.
    let storage_key_hash = keccak256(slot.as_slice());
    let storage_nibbles = Nibbles::unpack(storage_key_hash.as_slice());

    let storage_proof_nodes = proof
        .storage_proof
        .as_ref()
        .ok_or(MosooError::StorageSlotNotFound)?;

    let storage_value = proof.storage_value.clone();

    verify_proof(
        storage_root,
        storage_nibbles,
        storage_value.clone(),
        storage_proof_nodes,
    )
    .map_err(|_| MosooError::InvalidTrieProof)?;

    // Decode storage value: big-endian integer, zero-padded to 32 bytes.
    let raw = storage_value.unwrap_or_default();
    let mut value = [0u8; 32];
    let stripped = rlp_strip_prefix(&raw);
    let start = 32usize.saturating_sub(stripped.len());
    value[start..].copy_from_slice(stripped);

    Ok(VerifiedValue::StorageValue(value))
}

fn decode_account_balance(rlp: &[u8]) -> Result<U256, MosooError> {
    let fields = rlp_decode_account_fields(rlp)?;
    let balance_bytes = rlp_strip_prefix(fields[1]);
    Ok(U256::from_be_slice(balance_bytes))
}

fn decode_account_storage_root(rlp: &[u8]) -> Result<B256, MosooError> {
    let fields = rlp_decode_account_fields(rlp)?;
    let root_bytes = rlp_strip_prefix(fields[2]);
    if root_bytes.len() != 32 {
        return Err(MosooError::RlpDecodeFailed(format!(
            "storage_root is {} bytes, expected 32",
            root_bytes.len()
        )));
    }
    Ok(B256::from_slice(root_bytes))
}

/// Parse an RLP account list into its four field byte slices.
fn rlp_decode_account_fields(rlp: &[u8]) -> Result<[&[u8]; 4], MosooError> {
    let mut buf = rlp;

    if buf.is_empty() {
        return Err(MosooError::RlpDecodeFailed("empty account RLP".into()));
    }
    let first = buf[0];
    if first >= 0xf8 {
        let ll = (first - 0xf7) as usize;
        buf = &buf[1 + ll..];
    } else if first >= 0xc0 {
        buf = &buf[1..];
    } else {
        return Err(MosooError::RlpDecodeFailed(format!(
            "expected RLP list, got prefix 0x{first:02x}"
        )));
    }

    let mut fields: [&[u8]; 4] = [&[]; 4];
    for field in &mut fields {
        let (item, rest) = rlp_next_item(buf)?;
        *field = item;
        buf = rest;
    }
    Ok(fields)
}

fn rlp_next_item(buf: &[u8]) -> Result<(&[u8], &[u8]), MosooError> {
    if buf.is_empty() {
        return Err(MosooError::RlpDecodeFailed(
            "unexpected end of buffer".into(),
        ));
    }
    let first = buf[0] as usize;
    let (len, hlen) = if first < 0x80 {
        (1usize, 0usize)
    } else if first < 0xb8 {
        (first - 0x80, 1)
    } else if first < 0xc0 {
        let ll = first - 0xb7;
        let l = decode_be_usize(&buf[1..1 + ll]);
        (l, 1 + ll)
    } else if first < 0xf8 {
        (first - 0xc0, 1)
    } else {
        let ll = first - 0xf7;
        let l = decode_be_usize(&buf[1..1 + ll]);
        (l, 1 + ll)
    };
    let total = hlen + len;
    if buf.len() < total {
        return Err(MosooError::RlpDecodeFailed("truncated RLP item".into()));
    }
    Ok((&buf[..total], &buf[total..]))
}

pub fn rlp_strip_prefix(item: &[u8]) -> &[u8] {
    if item.is_empty() {
        return item;
    }
    let first = item[0] as usize;
    if first < 0x80 {
        item
    } else if first < 0xb8 {
        if item.len() <= 1 {
            &item[item.len()..]
        } else {
            &item[1..]
        }
    } else if first < 0xc0 {
        let ll = first - 0xb7;
        if item.len() < 1 + ll {
            &item[item.len()..]
        } else {
            &item[1 + ll..]
        }
    } else if first < 0xf8 {
        if item.len() <= 1 {
            &item[item.len()..]
        } else {
            &item[1..]
        }
    } else {
        let ll = first - 0xf7;
        if item.len() < 1 + ll {
            &item[item.len()..]
        } else {
            &item[1 + ll..]
        }
    }
}

fn decode_be_usize(bytes: &[u8]) -> usize {
    bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
}

pub mod test_helpers {
    use super::*;

    /// Helper to construct a single-leaf Merkle Patricia Trie proof for tests.
    pub fn build_leaf_mpt_proof(raw_key: &[u8], value: &[u8]) -> (B256, Vec<Bytes>) {
        use alloy_rlp::Encodable;
        use alloy_trie::nodes::LeafNode;

        let nibbles = Nibbles::unpack(raw_key);
        let leaf = LeafNode::new(nibbles, value.to_vec());
        let mut leaf_node = Vec::new();
        leaf.encode(&mut leaf_node);

        let root = keccak256(&leaf_node);
        (root, vec![Bytes::from(leaf_node)])
    }

    /// Construct a valid EIP-1559 receipt (type 0x02) containing an ERC-20 Transfer log.
    pub fn build_test_eip1559_transfer_receipt(
        emitter: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Vec<u8> {
        let transfer_sig = keccak256("Transfer(address,address,uint256)");
        let topic1 = B256::left_padding_from(from.as_slice());
        let topic2 = B256::left_padding_from(to.as_slice());

        // Topics RLP list
        let mut topics_payload = Vec::new();
        topics_payload.extend_from_slice(&alloy_rlp::encode(transfer_sig.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic1.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic2.0));
        let mut topics_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: topics_payload.len(),
        }
        .encode(&mut topics_rlp);
        topics_rlp.extend_from_slice(&topics_payload);

        // Data: amount as 32-byte BE
        let data_bytes = amount.to_be_bytes::<32>();
        let data_rlp = alloy_rlp::encode(&data_bytes[..]);

        // Log RLP: [address, topics, data]
        let mut log_payload = Vec::new();
        log_payload.extend_from_slice(&alloy_rlp::encode(emitter.as_slice()));
        log_payload.extend_from_slice(&topics_rlp);
        log_payload.extend_from_slice(&data_rlp);
        let mut log_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: log_payload.len(),
        }
        .encode(&mut log_rlp);
        log_rlp.extend_from_slice(&log_payload);

        // Logs list: [log_rlp]
        let mut logs_list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: log_rlp.len(),
        }
        .encode(&mut logs_list);
        logs_list.extend_from_slice(&log_rlp);

        // Receipt fields: [status=1, cumulative_gas=50000, bloom=256 zeros, logs]
        let status_rlp = alloy_rlp::encode(1u8);
        let gas_rlp = alloy_rlp::encode(50000u64);
        let bloom_bytes = [0u8; 256];
        let bloom_rlp = alloy_rlp::encode(&bloom_bytes[..]);

        let mut receipt_payload = Vec::new();
        receipt_payload.extend_from_slice(&status_rlp);
        receipt_payload.extend_from_slice(&gas_rlp);
        receipt_payload.extend_from_slice(&bloom_rlp);
        receipt_payload.extend_from_slice(&logs_list);

        let mut receipt_list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: receipt_payload.len(),
        }
        .encode(&mut receipt_list);
        receipt_list.extend_from_slice(&receipt_payload);

        // EIP-2718 typed receipt: prefix with transaction type byte 0x02
        let mut full_receipt = vec![0x02u8];
        full_receipt.extend_from_slice(&receipt_list);
        full_receipt
    }

    /// Construct a valid EIP-1559 receipt (type 0x02) containing a Native ETH bridge deposit log:
    /// Deposit(address sender, bytes32 recipient, uint256 amount).
    pub fn build_test_eip1559_deposit_receipt(
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
    ) -> Vec<u8> {
        let deposit_sig = keccak256("Deposit(address,bytes32,uint256)");
        let topic1 = B256::left_padding_from(sender.as_slice());
        let topic2 = B256::from(recipient);

        // Topics RLP list
        let mut topics_payload = Vec::new();
        topics_payload.extend_from_slice(&alloy_rlp::encode(deposit_sig.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic1.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic2.0));
        let mut topics_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: topics_payload.len(),
        }
        .encode(&mut topics_rlp);
        topics_rlp.extend_from_slice(&topics_payload);

        // Data: amount as 32-byte BE
        let data_bytes = amount.to_be_bytes::<32>();
        let data_rlp = alloy_rlp::encode(&data_bytes[..]);

        // Log RLP: [address, topics, data]
        let mut log_payload = Vec::new();
        log_payload.extend_from_slice(&alloy_rlp::encode(deposit_contract.as_slice()));
        log_payload.extend_from_slice(&topics_rlp);
        log_payload.extend_from_slice(&data_rlp);
        let mut log_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: log_payload.len(),
        }
        .encode(&mut log_rlp);
        log_rlp.extend_from_slice(&log_payload);

        // Logs list: [log_rlp]
        let mut logs_list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: log_rlp.len(),
        }
        .encode(&mut logs_list);
        logs_list.extend_from_slice(&log_rlp);

        // Receipt fields: [status=1, cumulative_gas=50000, bloom=256 zeros, logs]
        let status_rlp = alloy_rlp::encode(1u8);
        let gas_rlp = alloy_rlp::encode(50000u64);
        let bloom_bytes = [0u8; 256];
        let bloom_rlp = alloy_rlp::encode(&bloom_bytes[..]);

        let mut receipt_payload = Vec::new();
        receipt_payload.extend_from_slice(&status_rlp);
        receipt_payload.extend_from_slice(&gas_rlp);
        receipt_payload.extend_from_slice(&bloom_rlp);
        receipt_payload.extend_from_slice(&logs_list);

        let mut receipt_list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: receipt_payload.len(),
        }
        .encode(&mut receipt_list);
        receipt_list.extend_from_slice(&receipt_payload);

        let mut full_receipt = vec![0x02u8];
        full_receipt.extend_from_slice(&receipt_list);
        full_receipt
    }

    /// Construct a valid RLP-encoded Ethereum account with a specific native balance.
    pub fn build_test_account_balance_leaf(balance: U256) -> Vec<u8> {
        let nonce_rlp = alloy_rlp::encode(0u64);
        let balance_bytes = balance.to_be_bytes::<32>();
        let trimmed_balance = balance_bytes
            .iter()
            .position(|&b| b != 0)
            .map(|idx| &balance_bytes[idx..])
            .unwrap_or(&[0u8]);
        let balance_rlp = alloy_rlp::encode(trimmed_balance);
        let storage_root_rlp = alloy_rlp::encode([0u8; 32]);
        let code_hash_rlp = alloy_rlp::encode([0u8; 32]);

        let mut account_payload = Vec::new();
        account_payload.extend_from_slice(&nonce_rlp);
        account_payload.extend_from_slice(&balance_rlp);
        account_payload.extend_from_slice(&storage_root_rlp);
        account_payload.extend_from_slice(&code_hash_rlp);

        let mut account_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: account_payload.len(),
        }
        .encode(&mut account_rlp);
        account_rlp.extend_from_slice(&account_payload);
        account_rlp
    }

    /// Construct a complete single-leaf account balance MPT proof.
    pub fn build_test_account_balance_proof(
        address: Address,
        balance: U256,
    ) -> (B256, Vec<Bytes>, Vec<u8>) {
        let account_rlp = build_test_account_balance_leaf(balance);
        let key_hash = keccak256(address.as_slice());
        let (state_root, proof_nodes) = build_leaf_mpt_proof(key_hash.as_slice(), &account_rlp);
        (state_root, proof_nodes, account_rlp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn verified_value_eth_balance_as_bytes32() {
        let v = VerifiedValue::EthBalance(U256::from(256u64));
        let b = v.as_bytes32();
        assert_eq!(b[30], 0x01);
        assert_eq!(b[31], 0x00);
    }

    #[test]
    fn rlp_strip_single_byte() {
        assert_eq!(rlp_strip_prefix(&[0x01]), &[0x01]);
    }

    #[test]
    fn rlp_strip_short_string() {
        assert_eq!(rlp_strip_prefix(&[0x83, 0x61, 0x62, 0x63]), b"abc");
    }

    #[test]
    fn test_rlp_strip_prefix_out_of_bounds_safety() {
        // Truncated list prefix: byte claims 5-byte length payload, but item is only 2 bytes
        assert_eq!(rlp_strip_prefix(&[0xc5, 0x01]), &[0x01]);
        // Truncated long string prefix: claims 2 length bytes, but slice has only 1 byte
        assert_eq!(rlp_strip_prefix(&[0xb9]), &[] as &[u8]);
        // Truncated long list prefix: claims 3 length bytes, but slice has only 2 bytes
        assert_eq!(rlp_strip_prefix(&[0xfa, 0x01]), &[] as &[u8]);
        // Truncated short string: claims 3 bytes, only 1 present
        assert_eq!(rlp_strip_prefix(&[0x83, 0x42]), &[0x42]);
        // Empty slice safety
        assert_eq!(rlp_strip_prefix(&[]), &[] as &[u8]);
    }

    #[test]
    fn test_receipt_decoding_eip1559_transfer_log() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(1_000_000_000u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let transfer_sig = keccak256("Transfer(address,address,uint256)");

        let log =
            decode_and_validate_receipt(&receipt_rlp, 0, 0, Some(emitter), Some(transfer_sig))
                .expect("Valid EIP-1559 receipt must decode");

        assert_eq!(log.emitter, emitter);
        assert_eq!(log.topics.len(), 3);
        assert_eq!(log.topics[0], transfer_sig);
        assert_eq!(log.data, amount.to_be_bytes::<32>());
    }

    #[test]
    fn test_receipt_decoding_rejects_wrong_emitter() {
        let emitter = Address::repeat_byte(0xaa);
        let wrong_emitter = Address::repeat_byte(0xbb);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(500u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let transfer_sig = keccak256("Transfer(address,address,uint256)");

        let res = decode_and_validate_receipt(
            &receipt_rlp,
            0,
            0,
            Some(wrong_emitter),
            Some(transfer_sig),
        );

        assert!(matches!(res, Err(MosooError::EventEmitterMismatch { .. })));
    }

    #[test]
    fn test_receipt_decoding_rejects_wrong_topic() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(500u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let wrong_sig = keccak256("Approval(address,address,uint256)");

        let res = decode_and_validate_receipt(&receipt_rlp, 0, 0, Some(emitter), Some(wrong_sig));

        assert!(matches!(res, Err(MosooError::EventTopicMismatch { .. })));
    }

    #[test]
    fn test_receipt_decoding_rejects_out_of_bounds_log_index() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(500u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);

        let res = decode_and_validate_receipt(&receipt_rlp, 0, 5, Some(emitter), None);

        assert!(matches!(res, Err(MosooError::LogIndexOutOfBounds { .. })));
    }

    #[test]
    fn test_receipt_mpt_inclusion_verification_success() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(42_000_000u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);

        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: receipts_root.0,
        };

        let proof = ReceiptLogProof {
            tx_index,
            log_index: 0,
            expected_emitter: Some(emitter),
            expected_topic0: Some(keccak256("Transfer(address,address,uint256)")),
            receipt_proof: proof_nodes,
            receipt_rlp,
        };

        let verified =
            verify_receipt_log_proof(&proof, &header).expect("MPT receipt proof must verify");
        assert_eq!(verified.emitter, emitter);
        assert_eq!(verified.data, amount.to_be_bytes::<32>());
    }

    #[test]
    fn test_receipt_mpt_inclusion_corrupted_proof_rejected() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(42_000_000u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);

        let (receipts_root, mut proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

        // Corrupt the proof node
        let mut corrupted = proof_nodes[0].to_vec();
        corrupted[10] ^= 0xff;
        proof_nodes[0] = Bytes::from(corrupted);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: receipts_root.0,
        };

        let proof = ReceiptLogProof {
            tx_index,
            log_index: 0,
            expected_emitter: Some(emitter),
            expected_topic0: Some(keccak256("Transfer(address,address,uint256)")),
            receipt_proof: proof_nodes,
            receipt_rlp,
        };

        let res = verify_receipt_log_proof(&proof, &header);
        assert!(matches!(res, Err(MosooError::InvalidTrieProof)));
    }

    #[test]
    fn test_variable_length_log_data_prevents_silent_truncation_collision() {
        // Two distinct event payloads of 64 bytes with identical trailing 32 bytes
        let mut payload_a = vec![0x11u8; 32];
        payload_a.extend_from_slice(&[0xaa; 32]);

        let mut payload_b = vec![0x22u8; 32];
        payload_b.extend_from_slice(&[0xaa; 32]);

        let val_a = VerifiedValue::LogData(payload_a);
        let val_b = VerifiedValue::LogData(payload_b);

        let hash_a = val_a.as_bytes32();
        let hash_b = val_b.as_bytes32();

        // Under naive truncation, both would equal [0xaa; 32]
        // Under domain-separated hashing, they MUST NOT collide
        assert_ne!(
            hash_a, hash_b,
            "Distinct variable-length payloads with identical suffix MUST NOT collide"
        );
        assert_ne!(
            hash_a, [0xaa; 32],
            "Payload MUST NOT silently truncate to last 32 bytes"
        );
    }

    #[test]
    fn test_receipt_mpt_inclusion_wrong_root_rejected() {
        let emitter = Address::repeat_byte(0xaa);
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let amount = U256::from(42_000_000u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(emitter, from, to, amount);
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);

        let (_receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: [0xee; 32], // unrelated receipts root
        };

        let proof = ReceiptLogProof {
            tx_index,
            log_index: 0,
            expected_emitter: Some(emitter),
            expected_topic0: Some(keccak256("Transfer(address,address,uint256)")),
            receipt_proof: proof_nodes,
            receipt_rlp,
        };

        let res = verify_receipt_log_proof(&proof, &header);
        assert!(matches!(res, Err(MosooError::InvalidTrieProof)));
    }

    #[test]
    fn test_account_mpt_inclusion_verification_success() {
        let addr = Address::repeat_byte(0x42);
        let balance = U256::from(5_000_000_000_000_000_000u64); // 5 ETH

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(addr, balance);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x88; 32],
        };

        let proof = StateProof {
            target: ProofTarget::AccountBalance { address: addr },
            account_proof: proof_nodes,
            storage_proof: None,
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: None,
            receipt_value: None,
        };

        let verified =
            verify_state_proof(&proof, &header).expect("Account balance proof must verify");
        assert_eq!(verified, VerifiedValue::EthBalance(balance));
    }
}
