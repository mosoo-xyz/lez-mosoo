//! Mosoo Ethereum Consensus & State Attestation Program on LEZ v0.3.1 (`mosoo_lc`).
//!
//! Wraps genuine `mosoo-core` consensus verification, split BLS12-381 `blst` pairing,
//! fork-aware SSZ branch proofs, Merkle-Patricia Trie state proofs (`alloy-trie`),
//! composite predicates, and salted privacy shielding inside LEZ v0.3 `lee_core` `plan` + `apply`.

pub mod wire;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{AccountMeta, PdaSeed, Plan, PlanInput, ProgramEvent},
};
use mosoo_core::{
    crypto,
    error::MosooError,
    inclusion::StateProof,
    types::{
        compute_sync_committee_period, HeaderRecord, LightClientUpdate, NetworkConfig, Predicate,
        PrivacyMode, SyncCommittee, CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS,
    },
    verifier,
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use wire::*;

pub const E_BASE: u32 = 7300;
pub const E_ACCOUNTS: u32 = 7390;
pub const E_EXISTS: u32 = 7391;
pub const E_NO_INSTANCE: u32 = 7392;
pub const E_STALE: u32 = 7393;
pub const E_NO_JOB: u32 = 7394;
pub const E_JOB_STEP: u32 = 7395;

#[track_caller]
pub fn refuse(code: u32, why: &str) -> ! {
    panic!("E{code}: {why}")
}

#[track_caller]
fn refuse_unless(ok: bool, code: u32, why: &str) {
    if !ok {
        refuse(code, why);
    }
}

#[track_caller]
pub fn refuse_core(e: MosooError) -> ! {
    let offset = match e {
        MosooError::UnsupportedChain(_) => 1,
        MosooError::StaleUpdate { .. } => 2,
        MosooError::InsufficientParticipation { .. } => 3,
        MosooError::InvalidSignature => 4,
        MosooError::InvalidPublicKey(_) | MosooError::AggregationFailed => 5,
        MosooError::MissingCommitteeBranch | MosooError::SyncCommitteePeriodSkip { .. } => 6,
        MosooError::SyncCommitteeBranchInvalid => 7,
        MosooError::MissingExecutionPayload | MosooError::MissingExecutionPayloadBranch => 8,
        MosooError::ExecutionPayloadBranchInvalid => 9,
        MosooError::FinalityBranchInvalid => 10,
        MosooError::PredicateFailed => 11,
        MosooError::InvalidTrieProof
        | MosooError::AccountNotFound
        | MosooError::StorageSlotNotFound
        | MosooError::ReceiptNotFound(_)
        | MosooError::LogIndexOutOfBounds { .. }
        | MosooError::EventEmitterMismatch { .. }
        | MosooError::EventTopicMismatch { .. }
        | MosooError::RlpDecodeFailed(_) => 12,
        MosooError::DomainSeparationFailed => 13,
        MosooError::WeakSubjectivityExpired { .. } => 14,
        MosooError::UnconfiguredTrustedCheckpoint { .. }
        | MosooError::UntrustedCheckpoint { .. }
        | MosooError::UnconfiguredGenesisValidatorsRoot => 15,
        MosooError::InvalidBootstrap(_)
        | MosooError::BootstrapCommitteeBranchInvalid
        | MosooError::BootstrapNextCommitteeBranchInvalid => 16,
        _ => 17,
    };
    refuse(E_BASE + offset, &e.to_string());
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MosooInstance {
    pub instance_id: [u8; 32],
    pub chain_id: u64,
    pub checkpoint: [u8; 32],
    pub genesis_validators_root: [u8; 32],
    pub network_config: Option<WireNetworkConfig>,
    pub min_participation: u16,
    pub weak_subjectivity_window: u64,
    pub current_slot: u64,
    pub current_committee_root: [u8; 32],
    pub next_committee_root: Option<[u8; 32]>,
    pub current_header_hash: [u8; 32],
    pub current_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub execution_block_hash: [u8; 32],
    pub execution_state_root: [u8; 32],
    pub receipts_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MosooHeaderRecord {
    pub instance_id: [u8; 32],
    pub instance_pda: [u8; 32],
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    pub slot: u64,
    pub beacon_block_root: [u8; 32],
    pub execution_block_number: u64,
    pub execution_block_hash: [u8; 32],
    pub execution_state_root: [u8; 32],
    pub receipts_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MosooJob {
    pub prev_digest: [u8; 32],
    pub next_digest: [u8; 32],
    pub agg_pk: [u8; 48],
    pub msg_g2: [u8; 96],
    pub sig: Vec<u8>,
    pub miller_result: Option<Vec<u8>>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Accounts: `[instance_pda, header_pda]`.
    Init {
        instance_id: [u8; 32],
        chain_id: u64,
        checkpoint: [u8; 32],
        network_config: Option<WireNetworkConfig>,
        min_participation: u16,
        weak_subjectivity_window: u64,
        header: WireBeaconHeader,
        committee: WireSyncCommittee,
        committee_branch: Vec<[u8; 32]>,
        execution_payload_header: Option<WireExecutionPayloadHeader>,
        execution_branch: Option<Vec<[u8; 32]>>,
        execution_rlp: Option<Vec<u8>>,
    },
    /// Accounts: `[instance_pda, job_pda]`.
    Begin {
        instance_id: [u8; 32],
        current: MosooInstance,
        update: WireUpdate,
        committee: WireSyncCommittee,
        witness: WireKeyWitness,
    },
    /// Accounts: `[job_pda]`.
    Miller {
        instance_id: [u8; 32],
        job_id: [u8; 32],
    },
    /// Accounts: `[instance_pda, job_pda, header_pda]`.
    Finish {
        instance_id: [u8; 32],
        job_id: [u8; 32],
        current: MosooInstance,
        next: MosooInstance,
    },
    /// Accounts: `[header_pda]`.
    Attest {
        instance_id: [u8; 32],
        slot: u64,
        chain_id: u64,
        proof: WireStateProof,
        predicate: WirePredicate,
        privacy_salt: Option<[u8; 32]>,
        privacy_mode: Option<WirePrivacyMode>,
    },
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CheckQuery {
    pub chain_id: u64,
    pub proof: WireStateProof,
    pub predicate: WirePredicate,
    pub privacy_salt: Option<[u8; 32]>,
    pub privacy_mode: Option<WirePrivacyMode>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Create(MosooInstance),
    Record(MosooHeaderRecord),
    Expect([u8; 32]),
    Open(MosooJob),
    Miller,
    Close {
        prev: [u8; 32],
        next: [u8; 32],
    },
    Advance {
        prev: [u8; 32],
        next: MosooInstance,
    },
    Check(CheckQuery),
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct AdvancedEvent {
    pub instance_id: [u8; 32],
    pub slot: u64,
    pub period: u64,
    pub block_number: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct JobStepEvent {
    pub instance_id: [u8; 32],
    pub job_id: [u8; 32],
    pub step: u8,
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    Impl::hash_bytes(&buf)
        .as_bytes()
        .try_into()
        .expect("32 bytes")
}

pub fn digest<T: BorshSerialize>(t: &T) -> [u8; 32] {
    sha256(&[&borsh::to_vec(t).expect("infallible")])
}

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
#[repr(C, align(4))]
struct ShaTwoBlocks {
    b0: [u8; 64],
    b1: [u8; 64],
}

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
#[inline(always)]
fn sha256_64_pair_zkvm(blocks: &ShaTwoBlocks) -> [u8; 32] {
    extern "C" {
        fn sys_sha_buffer(
            out_state: *mut [u32; 8],
            in_state: *const [u32; 8],
            buf: *const u8,
            count: u32,
        );
    }
    const INIT: [u32; 8] = [
        0x6a09e667_u32.to_be(),
        0xbb67ae85_u32.to_be(),
        0x3c6ef372_u32.to_be(),
        0xa54ff53a_u32.to_be(),
        0x510e527f_u32.to_be(),
        0x9b05688c_u32.to_be(),
        0x1f83d9ab_u32.to_be(),
        0x5be0cd19_u32.to_be(),
    ];
    let mut out = [0u32; 8];
    // SAFETY: `ShaTwoBlocks` is 4-byte aligned and `128` bytes (2 SHA blocks) contiguous;
    // `out` and `INIT` are valid `[u32; 8]` digests for `sys_sha_buffer`.
    unsafe {
        sys_sha_buffer(&mut out, &INIT, blocks as *const ShaTwoBlocks as *const u8, 2);
        core::mem::transmute::<[u32; 8], [u8; 32]>(out)
    }
}

fn fast_sync_committee_root(committee: &WireSyncCommittee) -> Result<[u8; 32], MosooError> {
    if committee.pubkeys.len() != 512 {
        return Err(MosooError::InvalidSyncCommitteeLength {
            actual: committee.pubkeys.len(),
            expected: 512,
        });
    }
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    {
        let mut trailer = [0u8; 64];
        trailer[0] = 0x80;
        trailer[62] = 0x02; // 512 bits = 0x0200 big endian
        let mut blk = ShaTwoBlocks {
            b0: [0u8; 64],
            b1: trailer,
        };
        let mut leaves = [[0u8; 32]; 512];
        for (slot, pk) in leaves.iter_mut().zip(committee.pubkeys.iter()) {
            blk.b0[..48].copy_from_slice(&pk.0);
            *slot = sha256_64_pair_zkvm(&blk);
        }
        let mut len = 512usize;
        while len > 1 {
            let half = len / 2;
            for i in 0..half {
                blk.b0[..32].copy_from_slice(&leaves[2 * i]);
                blk.b0[32..64].copy_from_slice(&leaves[2 * i + 1]);
                leaves[i] = sha256_64_pair_zkvm(&blk);
            }
            len = half;
        }
        blk.b0[..48].copy_from_slice(&committee.aggregate_pubkey.0);
        blk.b0[48..64].fill(0);
        let agg_root = sha256_64_pair_zkvm(&blk);
        blk.b0[..32].copy_from_slice(&leaves[0]);
        blk.b0[32..64].copy_from_slice(&agg_root);
        Ok(sha256_64_pair_zkvm(&blk))
    }
    #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
    {
        crypto::hash_tree_root_sync_committee_iter(
            committee.pubkeys.iter().map(|pk| pk.0.as_slice()),
            &committee.aggregate_pubkey.0,
        )
    }
}

pub fn instance_account(me: &AccountId, instance_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(*instance_id))
}

pub fn job_id(current: &MosooInstance, update: &WireUpdate) -> [u8; 32] {
    sha256(&[&digest(current), &digest(update)])
}

pub fn job_account(me: &AccountId, instance_id: &[u8; 32], jid: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(
        me,
        &PdaSeed::new(sha256(&[b"mosoo_job", instance_id, jid])),
    )
}

pub fn header_account(me: &AccountId, instance_id: &[u8; 32], slot: u64) -> AccountId {
    AccountId::for_public_pda(
        me,
        &PdaSeed::new(sha256(&[b"mosoo_hdr", instance_id, &slot.to_le_bytes()])),
    )
}

fn event<T: BorshSerialize>(name: &str, body: &T) -> ProgramEvent {
    let sel = sha256(&[b"mosoo_lc::", name.as_bytes()]);
    ProgramEvent {
        selector: sel[..8].try_into().expect("8 bytes"),
        data: borsh::to_vec(body).expect("infallible"),
    }
}

fn rows<const N: usize>(input: &PlanInput) -> [AccountMeta; N] {
    <[AccountMeta; N]>::try_from(input.accounts.clone())
        .unwrap_or_else(|_| refuse(E_ACCOUNTS, "wrong number of accounts for this instruction"))
}

fn expect_own(row: &AccountMeta, me: &AccountId, id: AccountId, what: &str) {
    refuse_unless(
        row.account_id == id && row.program_account_id == *me,
        E_ACCOUNTS,
        what,
    );
}

pub fn header_record_from_instance(me: &AccountId, inst: &MosooInstance) -> MosooHeaderRecord {
    let pda = instance_account(me, &inst.instance_id);
    MosooHeaderRecord {
        instance_id: inst.instance_id,
        instance_pda: pda.value().to_owned(),
        chain_id: inst.chain_id,
        genesis_validators_root: inst.genesis_validators_root,
        slot: inst.current_slot,
        beacon_block_root: inst.current_header_hash,
        execution_block_number: inst.execution_block_number,
        execution_block_hash: inst.execution_block_hash,
        execution_state_root: inst.execution_state_root,
        receipts_root: inst.receipts_root,
    }
}

fn genesis_time_sec(chain_id: u64) -> Option<u64> {
    match chain_id {
        1 => Some(1_606_824_023),
        11_155_111 => Some(1_655_733_600),
        17_000 => Some(1_695_902_400),
        560_048 => Some(1_742_212_800),
        _ => None,
    }
}

fn stale_from_ms(chain_id: u64, slot: u64, window_slots: u64) -> Option<u64> {
    let gen_sec = genesis_time_sec(chain_id)?;
    let slot_sec = gen_sec.saturating_add(slot.saturating_mul(12));
    let stale_sec = slot_sec.saturating_add(window_slots.saturating_mul(12));
    Some(stale_sec.saturating_mul(1000))
}

#[must_use]
pub fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let me = input.self_account_id;
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Init {
            instance_id,
            chain_id,
            checkpoint,
            network_config,
            min_participation,
            weak_subjectivity_window,
            header,
            committee,
            committee_branch,
            execution_payload_header,
            execution_branch,
            execution_rlp,
        } => {
            let [inst_row, hdr_row] = rows::<2>(input);
            expect_own(
                &inst_row,
                &me,
                instance_account(&me, &instance_id),
                "first row must be the instance PDA",
            );

            let core_cfg: Option<NetworkConfig> = network_config.as_ref().map(Into::into);
            if !crypto::is_supported_chain_or_configured(chain_id, core_cfg.as_ref()) {
                refuse_core(MosooError::UnsupportedChain(chain_id));
            }
            let gvr = match core_cfg.as_ref() {
                Some(c) => c.genesis_validators_root,
                None => crypto::genesis_validators_root(chain_id),
            };
            if gvr == [0u8; 32] {
                refuse_core(MosooError::UnconfiguredGenesisValidatorsRoot);
            }
            refuse_unless(
                checkpoint != [0u8; 32],
                E_BASE + 16,
                "checkpoint root cannot be zero",
            );
            refuse_unless(
                header.slot > 0,
                E_BASE + 16,
                "bootstrap slot must be non-zero",
            );
            refuse_unless(
                (342..=512).contains(&min_participation),
                E_BASE + 16,
                "min_participation must be in 342..=512",
            );
            refuse_unless(
                weak_subjectivity_window > 0
                    && weak_subjectivity_window <= 1_728_000,
                E_BASE + 14,
                "weak_subjectivity_window out of bounds",
            );

            let core_hdr = (&header).into();
            let header_hash = crypto::hash_tree_root_beacon_header(&core_hdr);
            refuse_unless(
                header_hash == checkpoint,
                E_BASE + 16,
                "bootstrap header root does not match checkpoint",
            );

            let committee_leaf = fast_sync_committee_root(&committee)
                .unwrap_or_else(|e| refuse_core(e));
            let gindex = crypto::current_sync_committee_gindex(chain_id, header.slot);
            let computed_state =
                crypto::compute_branch_root_checked(committee_leaf, &committee_branch, gindex)
                    .unwrap_or_else(|e| refuse_core(e));
            refuse_unless(
                computed_state == header.state_root,
                E_BASE + 16,
                "bootstrap current_sync_committee branch invalid",
            );

            let (exec_block_num, exec_block_hash, exec_state_root, receipts_root) =
                if let (Some(payload), Some(branch)) =
                    (execution_payload_header.as_ref(), execution_branch.as_ref())
                {
                    let core_payload = payload.into();
                    verifier::verify_execution_payload_branch(
                        chain_id,
                        &core_payload,
                        &core_hdr,
                        branch,
                    )
                    .unwrap_or_else(|e| refuse_core(e));
                    let (bh, sr, rr) = verifier::verify_execution_roots_binding(
                        chain_id,
                        header.slot,
                        &core_payload,
                        execution_rlp.as_deref(),
                    )
                    .unwrap_or_else(|e| refuse_core(e));
                    (core_payload.block_number, bh, sr, rr)
                } else {
                    (0, [0u8; 32], [0u8; 32], [0u8; 32])
                };

            if let Some(limit_ms) = stale_from_ms(chain_id, header.slot, weak_subjectivity_window) {
                plan.timestamp_window(..limit_ms);
            }

            let inst = MosooInstance {
                instance_id,
                chain_id,
                checkpoint,
                genesis_validators_root: gvr,
                network_config,
                min_participation,
                weak_subjectivity_window,
                current_slot: header.slot,
                current_committee_root: committee_leaf,
                next_committee_root: None,
                current_header_hash: header_hash,
                current_state_root: header.state_root,
                execution_block_number: exec_block_num,
                execution_block_hash: exec_block_hash,
                execution_state_root: exec_state_root,
                receipts_root,
            };
            let hdr_rec = header_record_from_instance(&me, &inst);
            expect_own(
                &hdr_row,
                &me,
                header_account(&me, &instance_id, hdr_rec.slot),
                "second row must be the bootstrap header PDA",
            );

            plan.effect(&inst_row, &Effect::Create(inst));
            plan.effect(&hdr_row, &Effect::Record(hdr_rec));
        }

        Instruction::Begin {
            instance_id,
            current,
            update,
            committee,
            witness,
        } => {
            let [inst_row, job_row] = rows::<2>(input);
            expect_own(
                &inst_row,
                &me,
                instance_account(&me, &instance_id),
                "first row must be the instance PDA",
            );
            refuse_unless(
                current.instance_id == instance_id,
                E_BASE + 13,
                "current.instance_id mismatch",
            );
            let jid = job_id(&current, &update);
            expect_own(
                &job_row,
                &me,
                job_account(&me, &instance_id, &jid),
                "second row must be this update's job PDA",
            );

            let core_update: LightClientUpdate = (&update).into();
            if core_update.finalized_header.slot <= current.current_slot {
                refuse_core(MosooError::StaleUpdate {
                    update_slot: core_update.finalized_header.slot,
                    current_slot: current.current_slot,
                });
            }
            if core_update
                .finalized_header
                .slot
                .saturating_sub(current.current_slot)
                > current.weak_subjectivity_window
                || core_update
                    .signature_slot
                    .saturating_sub(current.current_slot)
                    > CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS
            {
                refuse_core(MosooError::WeakSubjectivityExpired {
                    update_slot: core_update.finalized_header.slot,
                    current_slot: current.current_slot,
                });
            }
            refuse_unless(
                core_update.attested_header.slot >= core_update.finalized_header.slot
                    && core_update.signature_slot >= core_update.attested_header.slot,
                E_BASE + 16,
                "invalid update slot ordering",
            );

            let store_period = compute_sync_committee_period(current.current_slot);
            let sig_period = compute_sync_committee_period(core_update.signature_slot);
            let fin_period = compute_sync_committee_period(core_update.finalized_header.slot);

            let expected_comm_root = if sig_period == store_period {
                current.current_committee_root
            } else if sig_period == store_period + 1 {
                current
                    .next_committee_root
                    .unwrap_or_else(|| refuse_core(MosooError::MissingCommitteeBranch))
            } else if sig_period > store_period + 1 {
                refuse_core(MosooError::SyncCommitteePeriodSkip {
                    sig_period,
                    current_period: store_period,
                });
            } else {
                refuse_core(MosooError::StaleUpdate {
                    update_slot: core_update.signature_slot,
                    current_slot: current.current_slot,
                });
            };
            if fin_period == store_period + 1 && current.next_committee_root.is_none() {
                refuse_core(MosooError::MissingCommitteeBranch);
            }
            if fin_period > store_period + 1 {
                refuse_core(MosooError::SyncCommitteePeriodSkip {
                    sig_period: fin_period,
                    current_period: store_period,
                });
            }

            let actual_comm_root = fast_sync_committee_root(&committee)
                .unwrap_or_else(|e| refuse_core(e));
            refuse_unless(
                actual_comm_root == expected_comm_root,
                E_BASE + 7,
                "supplied sync committee does not match tracked committee root",
            );
            let core_comm: SyncCommittee = (&committee).into();

            crypto::verify_sync_aggregate_lengths(
                &core_update.sync_aggregate.sync_committee_bits,
                &core_update.sync_aggregate.sync_committee_signature,
            )
            .unwrap_or_else(|e| refuse_core(e));
            let participation =
                crypto::count_participation(&core_update.sync_aggregate.sync_committee_bits);
            if participation < current.min_participation as usize {
                refuse_core(MosooError::InsufficientParticipation {
                    actual: participation,
                    required: current.min_participation as usize,
                });
            }

            let core_cfg: Option<NetworkConfig> = current.network_config.as_ref().map(Into::into);
            let signing_root = crypto::compute_signing_root_with_config(
                &core_update.attested_header,
                current.chain_id,
                core_update.signature_slot,
                core_cfg.as_ref(),
            )
            .unwrap_or_else(|e| refuse_core(e));
            let core_witness = (&witness).into();
            let agg_pk = crypto::verify_complement_aggregate_pubkey(
                &core_comm,
                &core_update.sync_aggregate.sync_committee_bits,
                &core_witness,
            )
            .unwrap_or_else(|e| refuse_core(e));
            let msg_g2 = crypto::blst_hash_to_g2(&signing_root);

            // Verify finality branch & execution payload roots using mosoo-core before opening Job.
            verifier::verify_finality_branch(
                current.chain_id,
                &core_update.finalized_header,
                &core_update.attested_header,
                &core_update.finality_branch,
            )
            .unwrap_or_else(|e| refuse_core(e));

            let payload = core_update
                .execution_payload_header
                .as_ref()
                .unwrap_or_else(|| refuse_core(MosooError::MissingExecutionPayload));
            let exec_branch = core_update
                .execution_branch
                .as_ref()
                .unwrap_or_else(|| refuse_core(MosooError::MissingExecutionPayloadBranch));
            verifier::verify_execution_payload_branch(
                current.chain_id,
                payload,
                &core_update.finalized_header,
                exec_branch,
            )
            .unwrap_or_else(|e| refuse_core(e));
            let (exec_hash, exec_state_root, receipts_root) = verifier::verify_execution_roots_binding(
                current.chain_id,
                core_update.finalized_header.slot,
                payload,
                core_update.execution_rlp.as_deref(),
            )
            .unwrap_or_else(|e| refuse_core(e));

            let mut rotated_current_comm = current.current_committee_root;
            let mut next_comm_root = current.next_committee_root;
            if fin_period > store_period {
                rotated_current_comm = next_comm_root
                    .take()
                    .unwrap_or_else(|| refuse_core(MosooError::MissingCommitteeBranch));
            }
            if let Some(ref nc) = core_update.next_sync_committee {
                let nb = core_update
                    .next_sync_committee_branch
                    .as_ref()
                    .unwrap_or_else(|| refuse_core(MosooError::MissingCommitteeBranch));
                verifier::verify_sync_committee_branch(
                    current.chain_id,
                    nc,
                    &core_update.attested_header,
                    nb,
                )
                .unwrap_or_else(|e| refuse_core(e));
                next_comm_root = Some(
                    crypto::hash_tree_root_sync_committee(nc).unwrap_or_else(|e| refuse_core(e)),
                );
            }

            let fin_hash = crypto::hash_tree_root_beacon_header(&core_update.finalized_header);
            let next_inst = MosooInstance {
                current_slot: core_update.finalized_header.slot,
                current_committee_root: rotated_current_comm,
                next_committee_root: next_comm_root,
                current_header_hash: fin_hash,
                current_state_root: core_update.finalized_header.state_root,
                execution_block_number: payload.block_number,
                execution_block_hash: exec_hash,
                execution_state_root: exec_state_root,
                receipts_root,
                ..current.clone()
            };

            if let Some(limit_ms) = stale_from_ms(
                current.chain_id,
                current.current_slot,
                current.weak_subjectivity_window,
            ) {
                plan.timestamp_window(..limit_ms);
            }

            let prev_d = digest(&current);
            let next_d = digest(&next_inst);
            let job = MosooJob {
                prev_digest: prev_d,
                next_digest: next_d,
                agg_pk,
                msg_g2,
                sig: core_update.sync_aggregate.sync_committee_signature,
                miller_result: None,
            };
            plan.effect(&inst_row, &Effect::Expect(prev_d));
            plan.effect(&job_row, &Effect::Open(job));
            plan.event(event(
                "JobStep",
                &JobStepEvent {
                    instance_id,
                    job_id: jid,
                    step: 1,
                },
            ));
        }

        Instruction::Miller {
            instance_id,
            job_id: jid,
        } => {
            let [job_row] = rows::<1>(input);
            expect_own(
                &job_row,
                &me,
                job_account(&me, &instance_id, &jid),
                "row must be the job PDA",
            );
            plan.effect(&job_row, &Effect::Miller);
            plan.event(event(
                "JobStep",
                &JobStepEvent {
                    instance_id,
                    job_id: jid,
                    step: 2,
                },
            ));
        }

        Instruction::Finish {
            instance_id,
            job_id: jid,
            current,
            next,
        } => {
            let [inst_row, job_row, hdr_row] = rows::<3>(input);
            expect_own(
                &inst_row,
                &me,
                instance_account(&me, &instance_id),
                "first row must be the instance PDA",
            );
            expect_own(
                &job_row,
                &me,
                job_account(&me, &instance_id, &jid),
                "second row must be the job PDA",
            );
            refuse_unless(
                next.instance_id == instance_id
                    && next.chain_id == current.chain_id
                    && next.current_slot > current.current_slot,
                E_BASE + 13,
                "invalid next instance transition",
            );

            if let Some(limit_ms) = stale_from_ms(
                current.chain_id,
                current.current_slot,
                current.weak_subjectivity_window,
            ) {
                plan.timestamp_window(..limit_ms);
            }

            let hdr_rec = header_record_from_instance(&me, &next);
            expect_own(
                &hdr_row,
                &me,
                header_account(&me, &instance_id, hdr_rec.slot),
                "third row must be the finalized header PDA",
            );

            let prev_d = digest(&current);
            let next_d = digest(&next);
            plan.effect(
                &job_row,
                &Effect::Close {
                    prev: prev_d,
                    next: next_d,
                },
            );
            plan.effect(
                &inst_row,
                &Effect::Advance {
                    prev: prev_d,
                    next: next.clone(),
                },
            );
            plan.effect(&hdr_row, &Effect::Record(hdr_rec.clone()));
            plan.event(event(
                "Advanced",
                &AdvancedEvent {
                    instance_id,
                    slot: hdr_rec.slot,
                    period: compute_sync_committee_period(hdr_rec.slot),
                    block_number: hdr_rec.execution_block_number,
                },
            ));
        }

        Instruction::Attest {
            instance_id,
            slot,
            chain_id,
            proof,
            predicate,
            privacy_salt,
            privacy_mode,
        } => {
            let [hdr_row] = rows::<1>(input);
            expect_own(
                &hdr_row,
                &me,
                header_account(&me, &instance_id, slot),
                "row must be the header PDA",
            );
            plan.effect(
                &hdr_row,
                &Effect::Check(CheckQuery {
                    chain_id,
                    proof,
                    predicate,
                    privacy_salt,
                    privacy_mode,
                }),
            );
        }
    }
    plan
}

fn put<T: BorshSerialize>(t: &T) -> Vec<u8> {
    borsh::to_vec(t).expect("infallible")
}

#[must_use]
pub fn apply(effect: Effect, pre: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Create(i) => {
            refuse_unless(
                pre.is_empty(),
                E_EXISTS,
                "an instance already exists at this id",
            );
            Some(put(&i))
        }
        Effect::Record(r) => {
            let new = put(&r);
            refuse_unless(
                pre.is_empty() || pre == new.as_slice(),
                E_EXISTS,
                "a different header record already exists for this slot",
            );
            Some(new)
        }
        Effect::Expect(d) => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(
                sha256(&[pre]) == d,
                E_STALE,
                "instance state changed since Begin was built",
            );
            None
        }
        Effect::Open(j) => {
            let new = put(&j);
            refuse_unless(
                pre.is_empty() || pre == new.as_slice(),
                E_EXISTS,
                "job already exists for this update",
            );
            if pre.is_empty() {
                Some(new)
            } else {
                None
            }
        }
        Effect::Miller => {
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: run Begin first");
            let mut j: MosooJob = borsh::from_slice(pre).expect("valid MosooJob");
            refuse_unless(
                j.miller_result.is_none(),
                E_JOB_STEP,
                "Miller already ran for this job: run Finish",
            );
            let ml = crypto::blst_two_miller_loops(&j.sig, &j.agg_pk, &j.msg_g2)
                .unwrap_or_else(|e| refuse_core(e));
            j.miller_result = Some(ml.to_vec());
            Some(put(&j))
        }
        Effect::Close { prev, next } => {
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: run Begin first");
            let j: MosooJob = borsh::from_slice(pre).expect("valid MosooJob");
            let ml = j
                .miller_result
                .as_ref()
                .unwrap_or_else(|| refuse(E_JOB_STEP, "Miller step has not run yet"));
            refuse_unless(
                j.prev_digest == prev && j.next_digest == next,
                E_STALE,
                "job commits to a different transition",
            );
            let valid = crypto::blst_final_exp_and_verify(ml).unwrap_or_else(|e| refuse_core(e));
            if !valid {
                refuse_core(MosooError::InvalidSignature);
            }
            Some(vec![])
        }
        Effect::Advance { prev, next } => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(
                sha256(&[pre]) == prev,
                E_STALE,
                "instance moved on before Finish completed",
            );
            Some(put(&next))
        }
        Effect::Check(q) => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no header recorded at this slot");
            let r: MosooHeaderRecord =
                borsh::from_slice(pre).expect("valid MosooHeaderRecord");
            refuse_unless(
                r.chain_id == q.chain_id,
                E_BASE + 13,
                "chain_id mismatch against authenticated HeaderRecord",
            );
            refuse_unless(
                r.execution_state_root != [0u8; 32] && r.receipts_root != [0u8; 32],
                E_BASE + 8,
                "header record has no authenticated execution roots",
            );
            let core_header = HeaderRecord {
                chain_id: r.chain_id,
                slot: r.slot,
                beacon_block_root: r.beacon_block_root,
                execution_block_hash: r.execution_block_hash,
                execution_state_root: r.execution_state_root,
                receipts_root: r.receipts_root,
            };
            let core_proof: StateProof = (&q.proof).into();
            let core_pred: Predicate = (&q.predicate).into();
            let core_mode: Option<PrivacyMode> = q.privacy_mode.as_ref().map(Into::into);
            let _stmt = verifier::verify_statement_against_authenticated_header(
                r.chain_id,
                r.instance_id,
                r.instance_pda,
                r.genesis_validators_root,
                &core_header,
                &core_proof,
                &core_pred,
                q.privacy_salt,
                core_mode,
                None,
            )
            .unwrap_or_else(|e| refuse_core(e));
            None
        }
    }
}
