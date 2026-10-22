//! Verification and state-transition logic for the Mosoo zkVM guest.
//!
//! Exposes the four SPEL instructions for Ethereum consensus tracking
//! and verified state attestation on the Logos Execution Zone.

use crate::{crypto, error::MosooError, inclusion, predicate, types::*};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginUpdateArgs {
    pub instance: InstanceAccount,
    pub update: LightClientUpdate,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MillerUpdateArgs {
    pub instance: InstanceAccount,
    pub job: JobAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishUpdateArgs {
    pub instance: InstanceAccount,
    pub job: JobAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestStateArgs {
    pub instance: InstanceAccount,
    pub header: HeaderRecord,
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    pub proof: inclusion::StateProof,
    pub predicate: Predicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstructionOutput {
    Initialized(InstanceAccount),
    JobCreated(JobAccount),
    JobMillerDone(JobAccount),
    UpdateFinished {
        updated_instance: InstanceAccount,
        header_record: HeaderRecord,
    },
    StatementIssued(VerifiedStatement),
}

pub fn handle_initialize(args: InitializeArgs) -> Result<InstructionOutput, MosooError> {
    // Guard: chain_id must be a supported Ethereum network
    if !crypto::is_supported_chain(args.chain_id) {
        return Err(MosooError::UnsupportedChain(args.chain_id));
    }

    // Guard: bootstrap slot must be non-zero (freshness / sanity).
    if args.bootstrap_header.slot == 0 {
        return Err(MosooError::InvalidBootstrap(
            "bootstrap slot must be non-zero".into(),
        ));
    }

    // Validation: the bootstrap committee must have exactly 512 pubkeys.
    if args.current_sync_committee.pubkeys.len() != 512 {
        return Err(MosooError::Internal(
            "bootstrap sync committee must have exactly 512 pubkeys".into(),
        ));
    }

    // Cryptographic validation: verify current_sync_committee branch against bootstrap_header.state_root.
    let committee_leaf = crypto::hash_tree_root_sync_committee(&args.current_sync_committee)?;
    let gindex: u64 = 54;
    let computed_root = crypto::compute_branch_root_checked(
        committee_leaf,
        &args.current_sync_committee_branch,
        gindex,
    )?;

    if computed_root != args.bootstrap_header.state_root {
        return Err(MosooError::BootstrapCommitteeBranchInvalid);
    }

    // Cryptographic validation: verify initial_next_committee branch against bootstrap_header.state_root if provided (gindex 55).
    if let Some(ref next_comm) = args.initial_next_committee {
        if next_comm.pubkeys.len() != 512 {
            return Err(MosooError::Internal(
                "bootstrap next sync committee must have exactly 512 pubkeys".into(),
            ));
        }
        let branch = args
            .initial_next_committee_branch
            .as_ref()
            .ok_or(MosooError::BootstrapNextCommitteeBranchInvalid)?;
        let next_leaf = crypto::hash_tree_root_sync_committee(next_comm)?;
        let computed_next = crypto::compute_branch_root_checked(next_leaf, branch, 55)?;
        if computed_next != args.bootstrap_header.state_root {
            return Err(MosooError::BootstrapNextCommitteeBranchInvalid);
        }
    }

    let header_hash = crypto::hash_tree_root_beacon_header(&args.bootstrap_header);

    let instance = InstanceAccount {
        chain_id: args.chain_id,
        current_header_hash: header_hash,
        current_state_root: args.bootstrap_header.state_root,
        current_slot: args.bootstrap_header.slot,
        current_sync_committee: args.current_sync_committee,
        next_sync_committee: args.initial_next_committee,
        bootstrap_slot: args.bootstrap_header.slot,
        initialized: true,
    };

    Ok(InstructionOutput::Initialized(instance))
}

pub fn handle_begin_update(args: BeginUpdateArgs) -> Result<InstructionOutput, MosooError> {
    let instance = &args.instance;
    let update = &args.update;

    // Guard: instance must be initialized.
    if !instance.initialized {
        return Err(MosooError::NotInitialized);
    }

    // Guard: update must advance the chain head.
    if update.finalized_header.slot <= instance.current_slot {
        return Err(MosooError::StaleUpdate {
            update_slot: update.finalized_header.slot,
            current_slot: instance.current_slot,
        });
    }

    // Guard: weak-subjectivity window check (max 54,000 epochs = 1,728,000 slots).
    // Trust assumptions:
    // 1. Initial bootstrap checkpoint is verified out-of-band to be fresh within the weak
    //    subjectivity period (~14 days / 100,800 slots) of real-time Ethereum network head.
    // 2. Incremental updates cannot jump beyond 1,728,000 slots to prevent long-range consensus forks.
    const WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 1_728_000;
    if update.finalized_header.slot > instance.current_slot + WEAK_SUBJECTIVITY_WINDOW_SLOTS {
        return Err(MosooError::WeakSubjectivityExpired {
            update_slot: update.finalized_header.slot,
            current_slot: instance.current_slot,
        });
    }

    // Strict length validation: 512 bits = exactly 64 bytes; signature = exactly 96 bytes.
    // Ensure the bitfield matches the Altair sync committee size before checking quorum.
    crypto::verify_sync_aggregate_lengths(
        &update.sync_aggregate.sync_committee_bits,
        &update.sync_aggregate.sync_committee_signature,
    )?;

    // Guard: >= 2/3 of 512 validators must have participated.
    let participation = crypto::count_participation(&update.sync_aggregate.sync_committee_bits);
    let threshold = (512usize * 2).div_ceil(3); // 342 validators
    if participation < threshold {
        return Err(MosooError::InsufficientParticipation {
            actual: participation,
            required: threshold,
        });
    }

    // Compute deterministic update digest binding this update across all 3 transactions.
    let update_digest = crypto::compute_update_digest(update);

    // Compute the signing root for the attested header.
    let signing_root = crypto::compute_signing_root(
        &update.attested_header,
        instance.chain_id,
        update.signature_slot,
    )?;

    // Aggregate the participating validators' public keys.
    let agg_pubkey_bytes = crypto::aggregate_participating_pubkeys(
        &instance.current_sync_committee,
        &update.sync_aggregate.sync_committee_bits,
    )?;

    // Compute hash_to_G2(signing_root) — the most expensive step in Begin.
    let msg_g2 = crypto::blst_hash_to_g2(&signing_root);

    let job = JobAccount {
        instance_chain_id: instance.chain_id,
        instance_slot: instance.current_slot,
        stage: JobStage::Miller,
        update_digest,
        update: update.clone(),
        miller_input: Some(MillerInput {
            agg_pubkey_compressed: agg_pubkey_bytes.to_vec(),
            msg_g2: msg_g2.to_vec(),
        }),
        miller_output: None,
        nonce: args.nonce,
    };

    Ok(InstructionOutput::JobCreated(job))
}

pub fn handle_miller_update(args: MillerUpdateArgs) -> Result<InstructionOutput, MosooError> {
    let mut job = args.job;

    // Cross-stage provenance and instance binding checks
    if job.instance_chain_id != args.instance.chain_id {
        return Err(MosooError::JobInstanceMismatch {
            expected: args.instance.chain_id,
            actual: job.instance_chain_id,
        });
    }

    if job.instance_slot != args.instance.current_slot {
        return Err(MosooError::JobSlotMismatch {
            expected: args.instance.current_slot,
            actual: job.instance_slot,
        });
    }

    if job.stage != JobStage::Miller {
        return Err(MosooError::WrongJobStage {
            expected: "Miller".into(),
            actual: format!("{:?}", job.stage),
        });
    }

    let computed_digest = crypto::compute_update_digest(&job.update);
    if computed_digest != job.update_digest {
        return Err(MosooError::JobDigestMismatch {
            computed: computed_digest,
            recorded: job.update_digest,
        });
    }

    crypto::verify_sync_aggregate_lengths(
        &job.update.sync_aggregate.sync_committee_bits,
        &job.update.sync_aggregate.sync_committee_signature,
    )?;

    let input = job
        .miller_input
        .as_ref()
        .ok_or(MosooError::MissingMillerInput)?;

    // Compute real Miller loops over the aggregated pubkey and signature.
    let miller_result = crypto::blst_two_miller_loops(
        job.update
            .sync_aggregate
            .sync_committee_signature
            .as_slice(),
        &input.agg_pubkey_compressed,
        &input.msg_g2,
    )?;

    job.miller_output = Some(MillerOutput {
        miller_result: miller_result.to_vec(),
    });
    job.stage = JobStage::Finish;

    Ok(InstructionOutput::JobMillerDone(job))
}

pub fn handle_finish_update(args: FinishUpdateArgs) -> Result<InstructionOutput, MosooError> {
    let mut instance = args.instance;
    let job = args.job;

    // Cross-stage provenance and instance binding checks
    if job.instance_chain_id != instance.chain_id {
        return Err(MosooError::JobInstanceMismatch {
            expected: instance.chain_id,
            actual: job.instance_chain_id,
        });
    }

    if job.instance_slot != instance.current_slot {
        return Err(MosooError::JobSlotMismatch {
            expected: instance.current_slot,
            actual: job.instance_slot,
        });
    }

    if job.stage != JobStage::Finish {
        return Err(MosooError::WrongJobStage {
            expected: "Finish".into(),
            actual: format!("{:?}", job.stage),
        });
    }

    let computed_digest = crypto::compute_update_digest(&job.update);
    if computed_digest != job.update_digest {
        return Err(MosooError::JobDigestMismatch {
            computed: computed_digest,
            recorded: job.update_digest,
        });
    }

    let output = job
        .miller_output
        .as_ref()
        .ok_or(MosooError::MissingMillerOutput)?;

    // Final exponentiation + pairing equality check.
    let valid = crypto::blst_final_exp_and_verify(&output.miller_result)?;
    if !valid {
        return Err(MosooError::InvalidSignature);
    }

    // BLS signature verified — proceed to Merkle branches.
    let update = &job.update;

    // Verify finality branch: finalized_header is in attested_header's state.
    verify_finality_branch(
        &update.finalized_header,
        &update.attested_header,
        &update.finality_branch,
    )?;

    // Period boundary committee rotation logic:
    // Sync committee period = 256 epochs = 8,192 slots.
    const SLOTS_PER_PERIOD: u64 = 8192;
    let current_period = instance.current_slot / SLOTS_PER_PERIOD;
    let update_period = update.finalized_header.slot / SLOTS_PER_PERIOD;

    if update_period > current_period {
        // We crossed into a new sync committee period.
        // The previously verified next_sync_committee now becomes active current_sync_committee.
        let next = instance
            .next_sync_committee
            .take()
            .ok_or(MosooError::MissingCommitteeBranch)?;
        instance.current_sync_committee = next;
    }

    // If this update provides the next sync committee (gindex 55), verify its branch and cache it for the next handoff.
    if let Some(ref next_committee) = update.next_sync_committee {
        let branch = update
            .next_sync_committee_branch
            .as_ref()
            .ok_or(MosooError::MissingCommitteeBranch)?;
        verify_sync_committee_branch(next_committee, &update.attested_header, branch)?;
        instance.next_sync_committee = Some(next_committee.clone());
    }

    // Verify execution payload branch (mandatory on post-merge Ethereum; generalized index 25 in BeaconBlockBody).
    let payload_header = update
        .execution_payload_header
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayload)?;
    let branch = update
        .execution_branch
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayloadBranch)?;

    verify_execution_payload_branch(payload_header, &update.finalized_header, branch)?;
    let execution_block_hash = payload_header.block_hash;
    let execution_state_root = payload_header.state_root;
    let receipts_root = payload_header.receipts_root;

    // Update instance head and state root anchor.
    instance.current_header_hash = crypto::hash_tree_root_beacon_header(&update.finalized_header);
    instance.current_state_root = update.finalized_header.state_root;
    instance.current_slot = update.finalized_header.slot;

    // Build the authenticated header record for consumer programs.
    let header_record = HeaderRecord {
        chain_id: instance.chain_id,
        slot: update.finalized_header.slot,
        beacon_block_root: crypto::hash_tree_root_beacon_header(&update.finalized_header),
        execution_block_hash,
        execution_state_root,
        receipts_root,
    };

    Ok(InstructionOutput::UpdateFinished {
        updated_instance: instance,
        header_record,
    })
}

pub fn handle_attest_state(args: AttestStateArgs) -> Result<InstructionOutput, MosooError> {
    // 1. Assert chain binding between the active instance and the requested header
    if args.header.chain_id != args.instance.chain_id {
        return Err(MosooError::DomainSeparationFailed);
    }

    // 2. The header slot cannot exceed the latest finalized slot of the instance
    if args.header.slot > args.instance.current_slot {
        return Err(MosooError::UnfinalizedHeader {
            header_slot: args.header.slot,
            current_slot: args.instance.current_slot,
        });
    }

    // 3. Cryptographic State & Provenance Binding:
    // When proving against the latest finalized block, the header's beacon root MUST match
    // the instance's active authenticated current_header_hash.
    if args.header.slot == args.instance.current_slot {
        if args.header.beacon_block_root != args.instance.current_header_hash {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
    } else {
        // Historical block root authentication:
        // In Ethereum consensus specs, BeaconState contains `block_roots: Vector[Root, 8192]`.
        // Field index of block_roots in BeaconState container = 5 (gindex = 32 + 5 = 37).
        // Each leaf within block_roots has index = slot % 8192.
        // Full generalized index in BeaconState = (37 << 13) | (slot % 8192).
        // Depth = 5 + 13 = 18.
        let branch = args
            .header_history_branch
            .as_ref()
            .ok_or(MosooError::UnauthenticatedHeaderRecord)?;
        let gindex: u64 = (37u64 << 13) | (args.header.slot % 8192);
        let computed_state_root =
            crypto::compute_branch_root_checked(args.header.beacon_block_root, branch, gindex)?;
        if computed_state_root != args.instance.current_state_root {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
    }

    // 4. Verify the Merkle-Patricia inclusion proof against the authenticated header.
    let verified_value = inclusion::verify_state_proof(&args.proof, &args.header)?;

    // 5. Derive collision-free deterministic subject key and provenance binding
    let (subject_key, proof_type_tag, binding) = match &args.proof.target {
        inclusion::ProofTarget::AccountBalance { address } => {
            use sha2::Digest;
            let mut addr = [0u8; 20];
            addr.copy_from_slice(address.as_slice());
            let key = sha2::Sha256::digest(address.as_slice());
            (
                key.into(),
                crate::types::PROOF_TYPE_ACCOUNT_BALANCE,
                crate::types::StatementBinding::Account { address: addr },
            )
        }
        inclusion::ProofTarget::StorageSlot { contract, slot } => {
            use sha2::Digest;
            let mut c = [0u8; 20];
            c.copy_from_slice(contract.as_slice());
            let mut s = [0u8; 32];
            s.copy_from_slice(slot.as_slice());
            let mut hasher = sha2::Sha256::new();
            hasher.update(contract.as_slice());
            hasher.update(slot.as_slice());
            (
                hasher.finalize().into(),
                crate::types::PROOF_TYPE_STORAGE_SLOT,
                crate::types::StatementBinding::Storage {
                    contract: c,
                    slot: s,
                },
            )
        }
        inclusion::ProofTarget::ReceiptLog {
            tx_index,
            log_index,
            emitter,
            topic0,
        } => {
            let mut emitter_arr = [0u8; 20];
            emitter_arr.copy_from_slice(emitter.as_slice());
            let mut topic0_arr = [0u8; 32];
            topic0_arr.copy_from_slice(topic0.as_slice());

            let key = predicate::derive_receipt_log_subject_key(
                &args.header.execution_block_hash,
                args.header.slot,
                *tx_index,
                *log_index,
                &emitter_arr,
                &topic0_arr,
            );
            (
                key,
                crate::types::PROOF_TYPE_RECEIPT_LOG,
                crate::types::StatementBinding::ReceiptLog {
                    emitter: emitter_arr,
                    topic0: topic0_arr,
                },
            )
        }
    };
    let statement = predicate::evaluate_with_binding(
        &args.predicate,
        &verified_value,
        args.header.chain_id,
        subject_key,
        proof_type_tag,
        binding,
    )?;

    Ok(InstructionOutput::StatementIssued(statement))
}

/// Verify that `finalized_header` appears in the `attested_header` state trie
/// at the known generalized index for the finalized checkpoint.
pub fn verify_finality_branch(
    finalized: &BeaconBlockHeader,
    attested: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    let leaf = crypto::hash_tree_root_beacon_header(finalized);
    // Generalized index for finalized_checkpoint.root in BeaconState = 105 (depth 6)
    let gindex: u64 = 105;
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != attested.state_root {
        return Err(MosooError::FinalityBranchInvalid);
    }
    Ok(())
}

/// Verify that `committee` appears in the `attested_header` state trie.
pub fn verify_sync_committee_branch(
    committee: &SyncCommittee,
    attested: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    // Spec-compliant SSZ hash-tree-root of the SyncCommittee struct.
    let leaf = crypto::hash_tree_root_sync_committee(committee)?;
    // Generalized index for next_sync_committee in BeaconState = 55 (depth 5)
    let gindex: u64 = 55;
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != attested.state_root {
        return Err(MosooError::SyncCommitteeBranchInvalid);
    }
    Ok(())
}

/// Verify that `payload_header` appears in the `finalized_header` body at generalized index 25.
pub fn verify_execution_payload_branch(
    payload: &ExecutionPayloadHeader,
    finalized: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    let leaf = crypto::hash_tree_root_execution_payload_header(payload)?;
    // Generalized index for execution_payload in BeaconBlockBody = 25 (depth 4)
    let gindex: u64 = 25;
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != finalized.body_root {
        return Err(MosooError::ExecutionPayloadBranchInvalid);
    }
    Ok(())
}
