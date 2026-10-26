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
    /// DepositETH(address sender, bytes32 recipient, uint256 amount, uint64 nonce) [canonical MosooLocker.sol event],
    /// Deposit(address sender, bytes32 recipient, uint256 amount), or Deposit(address sender, address recipient, uint256 amount).
    NativeEthDeposit {
        tx_index: u64,
        log_index: usize,
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
    },
    /// Prove an ERC-20 token deposit to MosooLocker bridge vault contract:
    /// DepositERC20(address indexed token, address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 nonce)
    Erc20Deposit {
        tx_index: u64,
        log_index: usize,
        deposit_contract: Address,
        token_contract: Address,
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
            if verified_log.topics.len() != 3 {
                return Err(MosooError::RlpDecodeFailed(format!(
                    "ERC-20 Transfer log must have exactly 3 topics (sig, from, to), got {}",
                    verified_log.topics.len()
                )));
            }
            let from_topic = verified_log.topics[1];
            if from_topic.0[0..12] != [0u8; 12] || &from_topic.0[12..32] != sender.as_slice() {
                return Err(MosooError::Internal(
                    "sender address mismatch in Transfer log".into(),
                ));
            }
            let to_topic = verified_log.topics[2];
            if to_topic.0[0..12] != [0u8; 12] {
                return Err(MosooError::Internal(
                    "to address in Transfer log must have 12 leading zero bytes".into(),
                ));
            }
            let matches_recipient = if to_topic.0 == *recipient {
                true
            } else if recipient[0..12] == [0u8; 12] {
                to_topic.0[12..32] == recipient[12..32]
            } else {
                false
            };
            if !matches_recipient {
                return Err(MosooError::RecipientMismatch);
            }
            if verified_log.data.len() != 32 {
                return Err(MosooError::Internal(format!(
                    "ERC-20 Transfer log data must be exactly 32 bytes (uint256 amount), got {}",
                    verified_log.data.len()
                )));
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
            let deposit_eth_canonical_topic0 = B256::from(alloy_primitives::keccak256(
                b"DepositETH(address,bytes32,uint256,uint64)",
            ));
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
            if sig == deposit_eth_canonical_topic0 {
                if verified_log.topics.len() != 4 {
                    return Err(MosooError::RlpDecodeFailed(format!(
                        "canonical DepositETH log must have exactly 4 topics (sig, sender, recipient, nonce), got {}",
                        verified_log.topics.len()
                    )));
                }
            } else if sig == deposit_topic0_bytes32 || sig == deposit_topic0_addr {
                if verified_log.topics.len() != 3 {
                    return Err(MosooError::RlpDecodeFailed(format!(
                        "legacy Deposit log must have exactly 3 topics (sig, sender, recipient), got {}",
                        verified_log.topics.len()
                    )));
                }
            } else {
                return Err(MosooError::EventTopicMismatch {
                    index: 0,
                    expected: format!(
                        "{deposit_eth_canonical_topic0:?} or {deposit_topic0_bytes32:?}"
                    ),
                    actual: format!("{sig:?}"),
                });
            }

            let from_topic = verified_log.topics[1];
            if &from_topic.0[12..32] != sender.as_slice() {
                return Err(MosooError::Internal(
                    "sender address mismatch in Deposit log".into(),
                ));
            }

            let to_topic = verified_log.topics[2];
            if sig == deposit_eth_canonical_topic0 || sig == deposit_topic0_bytes32 {
                // Canonical DepositETH(address,bytes32,uint256,uint64) and Deposit(address,bytes32,uint256):
                // Enforce strict exact 32-byte equality (Finding 2 / P1).
                if to_topic.0 != *recipient {
                    return Err(MosooError::RecipientMismatch);
                }
            } else if sig == deposit_topic0_addr {
                // Legacy Deposit(address sender, address recipient, uint256 amount):
                // The topic encodes an Ethereum address (20 bytes right-aligned, padded with 12 leading zeros).
                // Recipient must also be canonically padded with 12 leading zeros and match all 32 bytes exactly.
                // Partial prefix or truncated matches are strictly rejected.
                if to_topic.0[0..12] != [0u8; 12]
                    || recipient[0..12] != [0u8; 12]
                    || to_topic.0 != *recipient
                {
                    return Err(MosooError::RecipientMismatch);
                }
            }

            if verified_log.data.len() != 32 {
                return Err(MosooError::Internal(format!(
                    "deposit log data must be exactly 32 bytes, got {}",
                    verified_log.data.len()
                )));
            }
            Ok(VerifiedValue::LogData(verified_log.data))
        }
        ProofTarget::Erc20Deposit {
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            let deposit_erc20_topic0 = B256::from(alloy_primitives::keccak256(
                b"DepositERC20(address,address,bytes32,uint256,uint64)",
            ));
            let r_proof = ReceiptLogProof {
                tx_index: *tx_index,
                log_index: *log_index,
                expected_emitter: Some(*deposit_contract),
                expected_topic0: Some(deposit_erc20_topic0),
                receipt_proof: proof.receipt_proof.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_proof required for Erc20Deposit proof".into())
                })?,
                receipt_rlp: proof.receipt_value.clone().ok_or_else(|| {
                    MosooError::Internal("receipt_value required for Erc20Deposit proof".into())
                })?,
            };
            let verified_log = verify_receipt_log_proof(&r_proof, header)?;
            if verified_log.topics.len() != 4 {
                return Err(MosooError::RlpDecodeFailed(format!(
                    "DepositERC20 log must have exactly 4 topics (sig, token, sender, recipient), got {}",
                    verified_log.topics.len()
                )));
            }
            let token_topic = verified_log.topics[1];
            if &token_topic.0[12..32] != token_contract.as_slice() {
                return Err(MosooError::Internal(
                    "token contract mismatch in DepositERC20 log".into(),
                ));
            }
            let sender_topic = verified_log.topics[2];
            if &sender_topic.0[12..32] != sender.as_slice() {
                return Err(MosooError::Internal(
                    "sender address mismatch in DepositERC20 log".into(),
                ));
            }
            let recipient_topic = verified_log.topics[3];
            // Exact 32-byte matching for DepositERC20(..., bytes32 indexed lezRecipient, ...)
            if recipient_topic.0 != *recipient {
                return Err(MosooError::RecipientMismatch);
            }
            if verified_log.data.len() != 64 {
                return Err(MosooError::Internal(format!(
                    "DepositERC20 log data must be exactly 64 bytes (abi.encode(amount, nonce)), got {}",
                    verified_log.data.len()
                )));
            }
            // data is abi.encode(amount, nonce): first 32 bytes is amount
            Ok(VerifiedValue::LogData(verified_log.data[..32].to_vec()))
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

/// Decodes a verified DepositETH event log emitted by MosooLocker.sol.
///
/// Event signature: `DepositETH(address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 indexed nonce)`
/// Returns `(sender, recipient, amount, nonce)`.
pub fn decode_deposit_eth_log(
    log: &VerifiedLog,
) -> Result<(Address, [u8; 32], U256, u64), MosooError> {
    let deposit_eth_canonical_topic0 = B256::from(alloy_primitives::keccak256(
        b"DepositETH(address,bytes32,uint256,uint64)",
    ));
    let deposit_topic0_bytes32 = B256::from(alloy_primitives::keccak256(
        b"Deposit(address,bytes32,uint256)",
    ));
    let deposit_topic0_addr = B256::from(alloy_primitives::keccak256(
        b"Deposit(address,address,uint256)",
    ));

    if log.topics.is_empty() {
        return Err(MosooError::Internal("deposit log missing topics".into()));
    }
    let sig = log.topics[0];
    let nonce = if sig == deposit_eth_canonical_topic0 {
        if log.topics.len() != 4 {
            return Err(MosooError::RlpDecodeFailed(format!(
                "canonical DepositETH log must have exactly 4 topics (sig, sender, recipient, nonce), got {}",
                log.topics.len()
            )));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&log.topics[3].0[24..32]);
        u64::from_be_bytes(buf)
    } else if sig == deposit_topic0_bytes32 || sig == deposit_topic0_addr {
        if log.topics.len() != 3 {
            return Err(MosooError::RlpDecodeFailed(format!(
                "legacy Deposit log must have exactly 3 topics (sig, sender, recipient), got {}",
                log.topics.len()
            )));
        }
        0
    } else {
        return Err(MosooError::EventTopicMismatch {
            index: 0,
            expected: format!("{deposit_eth_canonical_topic0:?}"),
            actual: format!("{sig:?}"),
        });
    };

    let sender = Address::from_slice(&log.topics[1].0[12..32]);
    let recipient = log.topics[2].0;

    if log.data.len() != 32 {
        return Err(MosooError::Internal(format!(
            "deposit log data must be exactly 32 bytes (amount), got {}",
            log.data.len()
        )));
    }
    let mut amount_bytes = [0u8; 32];
    amount_bytes.copy_from_slice(&log.data[0..32]);
    let amount = U256::from_be_bytes(amount_bytes);

    Ok((sender, recipient, amount, nonce))
}

/// Decodes a verified DepositERC20 event log emitted by MosooLocker.sol.
///
/// Event signature: `DepositERC20(address indexed token, address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 nonce)`
/// Returns `(token, sender, recipient, amount, nonce)`.
pub fn decode_deposit_erc20_log(
    log: &VerifiedLog,
) -> Result<(Address, Address, [u8; 32], U256, u64), MosooError> {
    let deposit_erc20_topic0 = B256::from(alloy_primitives::keccak256(
        b"DepositERC20(address,address,bytes32,uint256,uint64)",
    ));

    if log.topics.len() != 4 {
        return Err(MosooError::RlpDecodeFailed(format!(
            "DepositERC20 log must have exactly 4 topics (sig, token, sender, recipient), got {}",
            log.topics.len()
        )));
    }
    if log.topics[0] != deposit_erc20_topic0 {
        return Err(MosooError::EventTopicMismatch {
            index: 0,
            expected: format!("{deposit_erc20_topic0:?}"),
            actual: format!("{:?}", log.topics[0]),
        });
    }

    let token = Address::from_slice(&log.topics[1].0[12..32]);
    let sender = Address::from_slice(&log.topics[2].0[12..32]);
    let recipient = log.topics[3].0;

    if log.data.len() != 64 {
        return Err(MosooError::Internal(format!(
            "DepositERC20 log data must be exactly 64 bytes (abi.encode(amount, nonce)), got {}",
            log.data.len()
        )));
    }
    let mut amount_bytes = [0u8; 32];
    amount_bytes.copy_from_slice(&log.data[0..32]);
    let amount = U256::from_be_bytes(amount_bytes);

    let mut nonce_buf = [0u8; 8];
    nonce_buf.copy_from_slice(&log.data[56..64]);
    let nonce = u64::from_be_bytes(nonce_buf);

    Ok((token, sender, recipient, amount, nonce))
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
        let len = decode_be_usize(&buf[1..1 + ll])?;
        let total = 1usize
            .checked_add(ll)
            .and_then(|v| v.checked_add(len))
            .ok_or_else(|| MosooError::RlpDecodeFailed("RLP list length overflow".into()))?;
        if buf.len() < total {
            return Err(MosooError::RlpDecodeFailed("truncated list payload".into()));
        }
        &buf[1 + ll..total]
    } else if first >= 0xc0 {
        let len = (first - 0xc0) as usize;
        let total = 1usize
            .checked_add(len)
            .ok_or_else(|| MosooError::RlpDecodeFailed("RLP list length overflow".into()))?;
        if buf.len() < total {
            return Err(MosooError::RlpDecodeFailed("truncated list payload".into()));
        }
        &buf[1..total]
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
    if state_root == B256::ZERO {
        return Err(MosooError::InvalidTrieProof);
    }
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
    if state_root == B256::ZERO {
        return Err(MosooError::InvalidTrieProof);
    }
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
        if buf.len() < 1 + ll {
            return Err(MosooError::RlpDecodeFailed(
                "truncated account RLP list length-of-length".into(),
            ));
        }
        let list_len = decode_be_usize(&buf[1..1 + ll])?;
        let total = 1usize
            .checked_add(ll)
            .and_then(|v| v.checked_add(list_len))
            .ok_or_else(|| {
                MosooError::RlpDecodeFailed("account RLP list length overflow".into())
            })?;
        if buf.len() < total {
            return Err(MosooError::RlpDecodeFailed(
                "truncated account RLP payload".into(),
            ));
        }
        buf = &buf[1 + ll..total];
    } else if first >= 0xc0 {
        let list_len = (first - 0xc0) as usize;
        let total = 1usize.checked_add(list_len).ok_or_else(|| {
            MosooError::RlpDecodeFailed("account RLP list length overflow".into())
        })?;
        if buf.len() < total {
            return Err(MosooError::RlpDecodeFailed(
                "truncated account RLP payload".into(),
            ));
        }
        buf = &buf[1..total];
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
        if buf.len() < 1 + ll {
            return Err(MosooError::RlpDecodeFailed(
                "truncated RLP string length-of-length".into(),
            ));
        }
        let l = decode_be_usize(&buf[1..1 + ll])?;
        (l, 1 + ll)
    } else if first < 0xf8 {
        (first - 0xc0, 1)
    } else {
        let ll = first - 0xf7;
        if buf.len() < 1 + ll {
            return Err(MosooError::RlpDecodeFailed(
                "truncated RLP list length-of-length".into(),
            ));
        }
        let l = decode_be_usize(&buf[1..1 + ll])?;
        (l, 1 + ll)
    };
    let total = hlen
        .checked_add(len)
        .ok_or_else(|| MosooError::RlpDecodeFailed("RLP item length overflow".into()))?;
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

fn decode_be_usize(bytes: &[u8]) -> Result<usize, MosooError> {
    if bytes.len() > core::mem::size_of::<usize>() {
        return Err(MosooError::RlpDecodeFailed(
            "RLP length field exceeds platform pointer width".into(),
        ));
    }
    let mut acc = 0usize;
    for &b in bytes {
        acc = acc
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or_else(|| MosooError::RlpDecodeFailed("RLP integer overflow".into()))?;
    }
    Ok(acc)
}

/// Extracts `(state_root, receipts_root, block_number)` from an RLP execution block header
/// and verifies that `keccak256(execution_rlp) == expected_block_hash`.
/// This cryptographically binds the state and receipts roots to the authenticated block hash
/// in forks where the beacon body only commits to the block hash (such as Gloas ePBS).
pub fn execution_header_roots(
    expected_block_hash: &[u8; 32],
    execution_rlp: &[u8],
) -> Result<([u8; 32], [u8; 32], u64), MosooError> {
    let hash = keccak256(execution_rlp);
    if &hash.0 != expected_block_hash {
        return Err(MosooError::GloasExecutionRlpMismatch);
    }
    let items = rlp_decode_list_items(execution_rlp)?;
    if items.len() < 15 {
        return Err(MosooError::RlpDecodeFailed(
            "execution block header RLP has fewer than 15 fields".into(),
        ));
    }
    let state_bytes = rlp_strip_prefix(items[3]);
    if state_bytes.len() != 32 {
        return Err(MosooError::RlpDecodeFailed(
            "invalid state_root length in execution block header RLP".into(),
        ));
    }
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(state_bytes);

    let receipts_bytes = rlp_strip_prefix(items[5]);
    if receipts_bytes.len() != 32 {
        return Err(MosooError::RlpDecodeFailed(
            "invalid receipts_root length in execution block header RLP".into(),
        ));
    }
    let mut receipts_root = [0u8; 32];
    receipts_root.copy_from_slice(receipts_bytes);

    let num_bytes = rlp_strip_prefix(items[8]);
    if num_bytes.len() > 8 {
        return Err(MosooError::RlpDecodeFailed(
            "block number in execution block header RLP exceeds u64".into(),
        ));
    }
    let mut block_number = 0u64;
    for &b in num_bytes {
        block_number = (block_number << 8) | (b as u64);
    }

    Ok((state_root, receipts_root, block_number))
}

pub mod test_helpers {
    use super::*;

    /// Construct a valid 15-field RLP execution block header for tests.
    pub fn build_test_execution_header_rlp(
        state_root: [u8; 32],
        receipts_root: [u8; 32],
        number: u64,
    ) -> Vec<u8> {
        let mut fields_payload = Vec::new();
        // 0: parent_hash
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 32]));
        // 1: ommers_hash
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 32]));
        // 2: beneficiary
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 20]));
        // 3: state_root
        fields_payload.extend_from_slice(&alloy_rlp::encode(state_root));
        // 4: transactions_root
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 32]));
        // 5: receipts_root
        fields_payload.extend_from_slice(&alloy_rlp::encode(receipts_root));
        // 6: logs_bloom
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 256]));
        // 7: difficulty
        fields_payload.extend_from_slice(&alloy_rlp::encode(0u64));
        // 8: number
        fields_payload.extend_from_slice(&alloy_rlp::encode(number));
        // 9: gas_limit
        fields_payload.extend_from_slice(&alloy_rlp::encode(30_000_000u64));
        // 10: gas_used
        fields_payload.extend_from_slice(&alloy_rlp::encode(21_000u64));
        // 11: timestamp
        fields_payload.extend_from_slice(&alloy_rlp::encode(1_700_000_000u64));
        // 12: extra_data
        fields_payload.extend_from_slice(&alloy_rlp::encode(&[][..]));
        // 13: mix_hash
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 32]));
        // 14: nonce
        fields_payload.extend_from_slice(&alloy_rlp::encode([0u8; 8]));

        let mut out = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: fields_payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&fields_payload);
        out
    }

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

    /// Construct an EIP-1559 receipt (type 0x02) with custom topics and payload data.
    pub fn build_custom_eip1559_transfer_receipt(
        emitter: Address,
        topics: Vec<B256>,
        data: Vec<u8>,
    ) -> Vec<u8> {
        let mut topics_payload = Vec::new();
        for topic in topics {
            topics_payload.extend_from_slice(&alloy_rlp::encode(topic.0));
        }
        let mut topics_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: topics_payload.len(),
        }
        .encode(&mut topics_rlp);
        topics_rlp.extend_from_slice(&topics_payload);

        let data_rlp = alloy_rlp::encode(&data[..]);

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

        let mut logs_list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: log_rlp.len(),
        }
        .encode(&mut logs_list);
        logs_list.extend_from_slice(&log_rlp);

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

    /// Construct a valid RLP-encoded Ethereum account with a custom storage root.
    pub fn build_test_account_storage_leaf(storage_root: [u8; 32]) -> Vec<u8> {
        let nonce_rlp = alloy_rlp::encode(0u64);
        let balance_rlp = alloy_rlp::encode(0u64);
        let storage_root_rlp = alloy_rlp::encode(storage_root);
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

    /// Construct a complete 2-level MPT proof for a contract account and one of its storage slots.
    pub fn build_test_storage_proof(
        contract: Address,
        slot: B256,
        value: [u8; 32],
    ) -> (B256, Vec<Bytes>, Vec<u8>, Vec<Bytes>, Vec<u8>) {
        // 1. Storage leaf and proof
        let trimmed = value
            .iter()
            .position(|&b| b != 0)
            .map(|i| &value[i..])
            .unwrap_or(&[0u8]);
        let storage_rlp = alloy_rlp::encode(trimmed);
        let storage_key_hash = keccak256(slot.as_slice());
        let (storage_root, storage_proof) =
            build_leaf_mpt_proof(storage_key_hash.as_slice(), &storage_rlp);

        // 2. Account leaf and proof in state trie
        let account_rlp = build_test_account_storage_leaf(storage_root.0);
        let account_key_hash = keccak256(contract.as_slice());
        let (state_root, account_proof) =
            build_leaf_mpt_proof(account_key_hash.as_slice(), &account_rlp);

        (
            state_root,
            account_proof,
            account_rlp,
            storage_proof,
            storage_rlp,
        )
    }

    /// Construct a complete MPT receipt proof for an EIP-1559 bridge deposit log.
    pub fn build_test_deposit_receipt_proof(
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
    ) -> (B256, Vec<Bytes>, Vec<u8>) {
        let receipt_rlp =
            build_test_eip1559_deposit_receipt(deposit_contract, sender, recipient, amount);
        let key_bytes = alloy_rlp::encode(0u64);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);
        (receipts_root, proof_nodes, receipt_rlp)
    }

    /// Construct a valid EIP-1559 receipt (type 0x02) containing the canonical MosooLocker DepositETH log:
    /// DepositETH(address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 indexed nonce).
    pub fn build_test_eip1559_deposit_eth_canonical_receipt(
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
        nonce: u64,
    ) -> Vec<u8> {
        let deposit_sig = keccak256("DepositETH(address,bytes32,uint256,uint64)");
        let topic1 = B256::left_padding_from(sender.as_slice());
        let topic2 = B256::from(recipient);
        let topic3 = B256::left_padding_from(&nonce.to_be_bytes());

        // Topics RLP list
        let mut topics_payload = Vec::new();
        topics_payload.extend_from_slice(&alloy_rlp::encode(deposit_sig.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic1.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic2.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic3.0));
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

    /// Construct a complete MPT receipt proof for canonical MosooLocker DepositETH log.
    pub fn build_test_deposit_eth_canonical_proof(
        deposit_contract: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
        nonce: u64,
    ) -> (B256, Vec<Bytes>, Vec<u8>) {
        let receipt_rlp = build_test_eip1559_deposit_eth_canonical_receipt(
            deposit_contract,
            sender,
            recipient,
            amount,
            nonce,
        );
        let key_bytes = alloy_rlp::encode(0u64);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);
        (receipts_root, proof_nodes, receipt_rlp)
    }

    /// Construct a valid EIP-1559 receipt (type 0x02) containing the canonical MosooLocker DepositERC20 log:
    /// DepositERC20(address indexed token, address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 nonce).
    pub fn build_test_eip1559_deposit_erc20_receipt(
        deposit_contract: Address,
        token: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
        nonce: u64,
    ) -> Vec<u8> {
        let deposit_sig = keccak256("DepositERC20(address,address,bytes32,uint256,uint64)");
        let topic1 = B256::left_padding_from(token.as_slice());
        let topic2 = B256::left_padding_from(sender.as_slice());
        let topic3 = B256::from(recipient);

        // Topics RLP list
        let mut topics_payload = Vec::new();
        topics_payload.extend_from_slice(&alloy_rlp::encode(deposit_sig.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic1.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic2.0));
        topics_payload.extend_from_slice(&alloy_rlp::encode(topic3.0));
        let mut topics_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: topics_payload.len(),
        }
        .encode(&mut topics_rlp);
        topics_rlp.extend_from_slice(&topics_payload);

        // Data: abi.encode(amount, nonce) -> 64 bytes
        let mut data_bytes = [0u8; 64];
        data_bytes[0..32].copy_from_slice(&amount.to_be_bytes::<32>());
        data_bytes[56..64].copy_from_slice(&nonce.to_be_bytes());
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

    /// Construct a complete MPT receipt proof for canonical MosooLocker DepositERC20 log.
    pub fn build_test_deposit_erc20_proof(
        deposit_contract: Address,
        token: Address,
        sender: Address,
        recipient: [u8; 32],
        amount: U256,
        nonce: u64,
    ) -> (B256, Vec<Bytes>, Vec<u8>) {
        let receipt_rlp = build_test_eip1559_deposit_erc20_receipt(
            deposit_contract,
            token,
            sender,
            recipient,
            amount,
            nonce,
        );
        let key_bytes = alloy_rlp::encode(0u64);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);
        (receipts_root, proof_nodes, receipt_rlp)
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

    #[test]
    fn test_rlp_truncated_length_of_length_returns_typed_error_without_panic() {
        // Long string prefix 0xb9 indicates 2-byte length follows, but buffer ends immediately
        let truncated_str = [0xb9u8];
        let res = rlp_next_item(&truncated_str);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Long list prefix 0xf9 indicates 2-byte length follows, but buffer ends immediately
        let truncated_list = [0xf9u8];
        let res = rlp_next_item(&truncated_list);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Long string prefix 0xba indicates 3-byte length follows, but only 1 byte present
        let truncated_str_partial = [0xbau8, 0x01];
        let res = rlp_next_item(&truncated_str_partial);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Long list prefix 0xfa indicates 3-byte length follows, but only 1 byte present
        let truncated_list_partial = [0xfau8, 0x01];
        let res = rlp_next_item(&truncated_list_partial);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));
    }

    #[test]
    fn test_rlp_decode_account_fields_truncated_returns_typed_error_without_panic() {
        // Truncated list prefix in account RLP
        let truncated_account_1 = [0xf8u8];
        assert!(matches!(
            rlp_decode_account_fields(&truncated_account_1),
            Err(MosooError::RlpDecodeFailed(_))
        ));

        let truncated_account_2 = [0xf9u8, 0x05];
        assert!(matches!(
            rlp_decode_account_fields(&truncated_account_2),
            Err(MosooError::RlpDecodeFailed(_))
        ));

        let empty_account = [];
        assert!(matches!(
            rlp_decode_account_fields(&empty_account),
            Err(MosooError::RlpDecodeFailed(_))
        ));
    }

    #[test]
    fn test_rlp_decode_list_items_overflow_safety() {
        // Buffer claiming 10,000 bytes payload when only 2 bytes exist
        let invalid_buf = [0xf9u8, 0x27, 0x10];
        let res = rlp_decode_list_items(&invalid_buf);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Empty buffer
        let empty_buf = [];
        let res = rlp_decode_list_items(&empty_buf);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));
    }

    #[test]
    fn test_storage_mpt_inclusion_verification_success() {
        let contract = Address::repeat_byte(0xbb);
        let slot = B256::repeat_byte(0x05);
        let mut expected_val = [0u8; 32];
        expected_val[31] = 42;

        let (state_root, account_proof, account_rlp, storage_proof, storage_rlp) =
            build_test_storage_proof(contract, slot, expected_val);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x88; 32],
        };

        let proof = StateProof {
            target: ProofTarget::StorageSlot { contract, slot },
            account_proof,
            storage_proof: Some(storage_proof),
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: Some(storage_rlp),
            receipt_value: None,
        };

        let verified = verify_state_proof(&proof, &header).expect("Storage slot proof must verify");
        assert_eq!(verified, VerifiedValue::StorageValue(expected_val));
    }

    #[test]
    fn test_deposit_receipt_mpt_inclusion_verification_success() {
        let deposit_contract = Address::repeat_byte(0x42);
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];
        let amount = U256::from(10_000_000_000u64);

        let (receipts_root, proof_nodes, receipt_rlp) =
            build_test_deposit_receipt_proof(deposit_contract, sender, recipient, amount);

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::NativeEthDeposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract,
                sender,
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let verified =
            verify_state_proof(&proof, &header).expect("Deposit receipt proof must verify");
        match verified {
            VerifiedValue::LogData(data) => {
                assert_eq!(data, amount.to_be_bytes::<32>());
            }
            _ => panic!("Expected LogData"),
        }
    }

    #[test]
    fn test_canonical_deposit_eth_mpt_inclusion_verification_success() {
        let deposit_contract = Address::repeat_byte(0x42);
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];
        let amount = U256::from(25_000_000_000_000_000_000u128); // 25 ETH
        let nonce = 7u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
            deposit_contract,
            sender,
            recipient,
            amount,
            nonce,
        );

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::NativeEthDeposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract,
                sender,
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let verified =
            verify_state_proof(&proof, &header).expect("Canonical DepositETH proof must verify");
        match verified {
            VerifiedValue::LogData(data) => {
                assert_eq!(data, amount.to_be_bytes::<32>());
            }
            _ => panic!("Expected LogData"),
        }
    }

    #[test]
    fn test_canonical_deposit_erc20_mpt_inclusion_verification_success() {
        let deposit_contract = Address::repeat_byte(0x42);
        let token = Address::repeat_byte(0xa0);
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];
        let amount = U256::from(100_000_000_000_000_000_000u128); // 100 tokens (18 dec)
        let nonce = 12u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            deposit_contract,
            token,
            sender,
            recipient,
            amount,
            nonce,
        );

        let header = HeaderRecord {
            chain_id: 1,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x66; 32],
            execution_state_root: [0x77; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract,
                token_contract: token,
                sender,
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let verified =
            verify_state_proof(&proof, &header).expect("Canonical DepositERC20 proof must verify");
        match verified {
            VerifiedValue::LogData(data) => {
                assert_eq!(data, amount.to_be_bytes::<32>());
            }
            _ => panic!("Expected LogData"),
        }
    }

    #[test]
    fn test_decode_deposit_eth_fail_closed_on_malformed_topics() {
        let deposit_eth_sig = B256::from(alloy_primitives::keccak256(
            b"DepositETH(address,bytes32,uint256,uint64)",
        ));
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];
        let amount = U256::from(1_000_000_000u64);

        // Truncated to 3 topics (missing nonce topic)
        let malformed_log = VerifiedLog {
            emitter: Address::repeat_byte(0x42),
            topics: vec![
                deposit_eth_sig,
                B256::left_padding_from(sender.as_slice()),
                B256::from(recipient),
            ],
            data: amount.to_be_bytes::<32>().to_vec(),
            tx_index: 0,
            log_index: 0,
        };

        let res = decode_deposit_eth_log(&malformed_log);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Superfluous 5 topics
        let mut superfluous_topics = malformed_log.topics.clone();
        superfluous_topics.push(B256::repeat_byte(0x01));
        superfluous_topics.push(B256::repeat_byte(0x02));
        let malformed_log_5 = VerifiedLog {
            topics: superfluous_topics,
            ..malformed_log
        };
        let res2 = decode_deposit_eth_log(&malformed_log_5);
        assert!(matches!(res2, Err(MosooError::RlpDecodeFailed(_))));
    }

    #[test]
    fn test_decode_deposit_eth_fail_closed_on_malformed_data() {
        let deposit_eth_sig = B256::from(alloy_primitives::keccak256(
            b"DepositETH(address,bytes32,uint256,uint64)",
        ));
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];
        let nonce = 5u64;

        let base_log = VerifiedLog {
            emitter: Address::repeat_byte(0x42),
            topics: vec![
                deposit_eth_sig,
                B256::left_padding_from(sender.as_slice()),
                B256::from(recipient),
                B256::left_padding_from(&nonce.to_be_bytes()),
            ],
            data: vec![0u8; 16], // Truncated data: 16 bytes instead of 32
            tx_index: 0,
            log_index: 0,
        };

        let res = decode_deposit_eth_log(&base_log);
        assert!(matches!(res, Err(MosooError::Internal(_))));

        // Over-sized data: 64 bytes instead of 32
        let oversized_log = VerifiedLog {
            data: vec![0u8; 64],
            ..base_log
        };
        let res2 = decode_deposit_eth_log(&oversized_log);
        assert!(matches!(res2, Err(MosooError::Internal(_))));
    }

    #[test]
    fn test_decode_deposit_erc20_fail_closed_on_malformed_topics_and_data() {
        let deposit_erc20_sig = B256::from(alloy_primitives::keccak256(
            b"DepositERC20(address,address,bytes32,uint256,uint64)",
        ));
        let token = Address::repeat_byte(0xa0);
        let sender = Address::repeat_byte(0x11);
        let recipient = [0x22u8; 32];

        // Truncated to 3 topics
        let malformed_topics_log = VerifiedLog {
            emitter: Address::repeat_byte(0x42),
            topics: vec![
                deposit_erc20_sig,
                B256::left_padding_from(token.as_slice()),
                B256::left_padding_from(sender.as_slice()),
            ],
            data: vec![0u8; 64],
            tx_index: 0,
            log_index: 0,
        };
        let res = decode_deposit_erc20_log(&malformed_topics_log);
        assert!(matches!(res, Err(MosooError::RlpDecodeFailed(_))));

        // Valid 4 topics but truncated data: only 32 bytes instead of 64
        let malformed_data_log = VerifiedLog {
            emitter: Address::repeat_byte(0x42),
            topics: vec![
                deposit_erc20_sig,
                B256::left_padding_from(token.as_slice()),
                B256::left_padding_from(sender.as_slice()),
                B256::from(recipient),
            ],
            data: vec![0u8; 32],
            tx_index: 0,
            log_index: 0,
        };
        let res2 = decode_deposit_erc20_log(&malformed_data_log);
        assert!(matches!(res2, Err(MosooError::Internal(_))));

        // Valid topics and valid 64 bytes data succeeds with exact nonce
        let mut valid_data = vec![0u8; 64];
        valid_data[31] = 42; // amount = 42
        valid_data[63] = 9; // nonce = 9
        let valid_log = VerifiedLog {
            data: valid_data,
            ..malformed_data_log
        };
        let (dec_tok, dec_snd, dec_rec, dec_amt, dec_nonce) =
            decode_deposit_erc20_log(&valid_log).expect("Exact 64-byte log MUST decode");
        assert_eq!(dec_tok, token);
        assert_eq!(dec_snd, sender);
        assert_eq!(dec_rec, recipient);
        assert_eq!(dec_amt, U256::from(42u64));
        assert_eq!(dec_nonce, 9u64);
    }
}
