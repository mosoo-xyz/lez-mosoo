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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstructionOutput {
    Initialized(InstanceAccount),
    JobCreated(JobAccount),
    JobMillerDone(JobAccount),
    UpdateFinished {
        updated_instance: InstanceAccount,
        header_record: HeaderRecord,
        closed_job: JobAccount,
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

    // Mandatory Weak Subjectivity Freshness Guard:
    // 1. trusted_head_slot cannot be 0.
    // 2. trusted_head_slot cannot precede the bootstrap header slot.
    // 3. bootstrap checkpoint must be within the 1,728,000 slot weak-subjectivity threshold (54,000 epochs / ~240 days).
    const WEAK_SUBJECTIVITY_SLOTS: u64 = 1_728_000;
    if args.trusted_head_slot == 0 {
        return Err(MosooError::InvalidBootstrap(
            "trusted_head_slot is mandatory for weak-subjectivity verification and cannot be zero"
                .into(),
        ));
    }
    if args.trusted_head_slot < args.bootstrap_header.slot {
        return Err(MosooError::InvalidBootstrap(format!(
            "trusted_head_slot ({}) cannot precede bootstrap_header.slot ({})",
            args.trusted_head_slot, args.bootstrap_header.slot
        )));
    }
    if args.trusted_head_slot > args.bootstrap_header.slot + WEAK_SUBJECTIVITY_SLOTS {
        return Err(MosooError::WeakSubjectivityExpired {
            update_slot: args.bootstrap_header.slot,
            current_slot: args.trusted_head_slot,
        });
    }

    // Cryptographic validation: verify current_sync_committee branch against bootstrap_header.state_root
    // using fork-aware SSZ generalized index (54 for Altair/Deneb, 86 for Electra/Fulu, 2945 for Gloas).
    let committee_leaf = crypto::hash_tree_root_sync_committee(&args.current_sync_committee)?;
    let gindex = crypto::current_sync_committee_gindex(args.chain_id, args.bootstrap_header.slot);
    let computed_root = crypto::compute_branch_root_checked(
        committee_leaf,
        &args.current_sync_committee_branch,
        gindex,
    )?;

    if computed_root != args.bootstrap_header.state_root {
        return Err(MosooError::BootstrapCommitteeBranchInvalid);
    }

    // Cryptographic validation: verify initial_next_committee branch against bootstrap_header.state_root if provided.
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
        let next_gindex =
            crypto::next_sync_committee_gindex(args.chain_id, args.bootstrap_header.slot);
        let computed_next = crypto::compute_branch_root_checked(next_leaf, branch, next_gindex)?;
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

/// Recovers a light client instance that has stalled beyond the weak-subjectivity window (>1,728,000 slots).
/// Re-anchors the instance to an authenticated contemporary checkpoint after network recovery.
pub fn handle_recover_instance(
    args: crate::types::RecoverInstanceArgs,
) -> Result<InstructionOutput, MosooError> {
    let mut instance = args.instance;
    if !instance.initialized {
        return Err(MosooError::NotInitialized);
    }
    const WEAK_SUBJECTIVITY_SLOTS: u64 = 1_728_000;
    // Guard: recovery is only permitted if the instance has stalled past the weak-subjectivity threshold
    if args.current_network_slot <= instance.current_slot + WEAK_SUBJECTIVITY_SLOTS {
        return Err(MosooError::Internal(
            "instance is not stale; normal incremental updates must be used".into(),
        ));
    }
    // Anti-rollback guard: recovery checkpoint must strictly advance the instance slot
    if args.new_bootstrap_header.slot <= instance.current_slot {
        return Err(MosooError::Internal(
            "recovery checkpoint slot must strictly exceed current instance slot (no backward rollback)".into(),
        ));
    }
    // Freshness guard: recovery checkpoint itself must not be expired relative to current network slot
    if args.current_network_slot > args.new_bootstrap_header.slot + WEAK_SUBJECTIVITY_SLOTS {
        return Err(MosooError::WeakSubjectivityExpired {
            update_slot: args.new_bootstrap_header.slot,
            current_slot: args.current_network_slot,
        });
    }
    // Verify the new bootstrap checkpoint
    let committee_leaf = crypto::hash_tree_root_sync_committee(&args.new_sync_committee)?;
    let gindex =
        crypto::current_sync_committee_gindex(instance.chain_id, args.new_bootstrap_header.slot);
    let computed_root = crypto::compute_branch_root_checked(
        committee_leaf,
        &args.new_sync_committee_branch,
        gindex,
    )?;
    if computed_root != args.new_bootstrap_header.state_root {
        return Err(MosooError::BootstrapCommitteeBranchInvalid);
    }

    if let Some(ref next_comm) = args.initial_next_committee {
        let branch = args
            .initial_next_committee_branch
            .as_ref()
            .ok_or(MosooError::BootstrapNextCommitteeBranchInvalid)?;
        let next_leaf = crypto::hash_tree_root_sync_committee(next_comm)?;
        let next_gindex =
            crypto::next_sync_committee_gindex(instance.chain_id, args.new_bootstrap_header.slot);
        let computed_next = crypto::compute_branch_root_checked(next_leaf, branch, next_gindex)?;
        if computed_next != args.new_bootstrap_header.state_root {
            return Err(MosooError::BootstrapNextCommitteeBranchInvalid);
        }
    }

    instance.current_header_hash = crypto::hash_tree_root_beacon_header(&args.new_bootstrap_header);
    instance.current_state_root = args.new_bootstrap_header.state_root;
    instance.current_slot = args.new_bootstrap_header.slot;
    instance.current_sync_committee = args.new_sync_committee;
    instance.next_sync_committee = args.initial_next_committee;

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
    //    subjectivity operational window (14–30 days) up to the consensus safety bound (1,728,000 slots / ~240 days).
    // 2. Incremental updates cannot jump beyond 1,728,000 slots to prevent long-range consensus forks.
    const WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 1_728_000;
    if update.finalized_header.slot > instance.current_slot + WEAK_SUBJECTIVITY_WINDOW_SLOTS {
        return Err(MosooError::WeakSubjectivityExpired {
            update_slot: update.finalized_header.slot,
            current_slot: instance.current_slot,
        });
    }

    // Temporal consistency: attested header cannot precede finalized header,
    // and signature slot must be at or after attested header slot.
    if update.attested_header.slot < update.finalized_header.slot {
        return Err(MosooError::Internal(
            "attested header slot must be >= finalized header slot".into(),
        ));
    }
    if update.signature_slot < update.attested_header.slot {
        return Err(MosooError::Internal(
            "signature slot must be >= attested header slot".into(),
        ));
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
        instance.chain_id,
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

    // If this update provides the next sync committee, verify its branch and cache it for the next handoff.
    if let Some(ref next_committee) = update.next_sync_committee {
        let branch = update
            .next_sync_committee_branch
            .as_ref()
            .ok_or(MosooError::MissingCommitteeBranch)?;
        verify_sync_committee_branch(
            instance.chain_id,
            next_committee,
            &update.attested_header,
            branch,
        )?;
        instance.next_sync_committee = Some(next_committee.clone());
    }

    // Verify execution payload branch.
    let payload_header = update
        .execution_payload_header
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayload)?;
    let branch = update
        .execution_branch
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayloadBranch)?;

    verify_execution_payload_branch(
        instance.chain_id,
        payload_header,
        &update.finalized_header,
        branch,
    )?;
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

    let mut closed_job = job;
    closed_job.stage = JobStage::Done;

    Ok(InstructionOutput::UpdateFinished {
        updated_instance: instance,
        header_record,
        closed_job,
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
        // Guard: block_roots is a cyclic ring buffer of 8,192 slots. Proving blocks older than
        // 8,192 slots requires historical_summaries / historical_roots.
        const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
        if args.instance.current_slot.saturating_sub(args.header.slot) > SLOTS_PER_HISTORICAL_ROOT {
            return Err(MosooError::Internal(
                "historical block is older than 8,192 slots; outside BeaconState.block_roots ring buffer".into(),
            ));
        }

        let branch = args
            .header_history_branch
            .as_ref()
            .ok_or(MosooError::UnauthenticatedHeaderRecord)?;
        let gindex = crypto::historical_block_roots_gindex(
            args.instance.chain_id,
            args.instance.current_slot,
            args.header.slot,
        );
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
        inclusion::ProofTarget::Erc20Transfer {
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            let mut tc = [0u8; 20];
            tc.copy_from_slice(token_contract.as_slice());
            let mut snd = [0u8; 20];
            snd.copy_from_slice(sender.as_slice());
            let key = predicate::derive_erc20_transfer_subject_key(
                &args.header.execution_block_hash,
                args.header.slot,
                *tx_index,
                *log_index,
                &tc,
                &snd,
                recipient,
            );
            (
                key,
                crate::types::PROOF_TYPE_ERC20_TRANSFER,
                crate::types::StatementBinding::Erc20Transfer {
                    execution_block_hash: args.header.execution_block_hash,
                    slot: args.header.slot,
                    tx_index: *tx_index,
                    log_index: *log_index,
                    token_contract: tc,
                    sender: snd,
                    recipient: *recipient,
                },
            )
        }
        inclusion::ProofTarget::NativeEthDeposit {
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        } => {
            let mut dc = [0u8; 20];
            dc.copy_from_slice(deposit_contract.as_slice());
            let mut snd = [0u8; 20];
            snd.copy_from_slice(sender.as_slice());
            let key = predicate::derive_eth_deposit_subject_key(
                &args.header.execution_block_hash,
                args.header.slot,
                *tx_index,
                *log_index,
                &dc,
                &snd,
                recipient,
            );
            (
                key,
                crate::types::PROOF_TYPE_ETH_DEPOSIT,
                crate::types::StatementBinding::NativeEthDeposit {
                    execution_block_hash: args.header.execution_block_hash,
                    slot: args.header.slot,
                    tx_index: *tx_index,
                    log_index: *log_index,
                    deposit_contract: dc,
                    sender: snd,
                    recipient: *recipient,
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

    // Guard: Fail-closed architecture. If predicate does not hold, NEVER issue a statement.
    if !statement.predicate_holds {
        return Err(MosooError::PredicateFailed);
    }

    Ok(InstructionOutput::StatementIssued(statement))
}

/// Verify that `finalized_header` appears in the `attested_header` state trie
/// at the fork's generalized index for the finalized checkpoint.
pub fn verify_finality_branch(
    chain_id: u64,
    finalized: &BeaconBlockHeader,
    attested: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    let leaf = crypto::hash_tree_root_beacon_header(finalized);
    let gindex = crypto::finalized_root_gindex(chain_id, attested.slot);
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != attested.state_root {
        return Err(MosooError::FinalityBranchInvalid);
    }
    Ok(())
}

/// Verify that `committee` appears in the `attested_header` state trie.
pub fn verify_sync_committee_branch(
    chain_id: u64,
    committee: &SyncCommittee,
    attested: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    // Spec-compliant SSZ hash-tree-root of the SyncCommittee struct.
    let leaf = crypto::hash_tree_root_sync_committee(committee)?;
    let gindex = crypto::next_sync_committee_gindex(chain_id, attested.slot);
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != attested.state_root {
        return Err(MosooError::SyncCommitteeBranchInvalid);
    }
    Ok(())
}

/// Verify that `payload_header` appears in the `finalized_header` body at the fork's generalized index.
pub fn verify_execution_payload_branch(
    chain_id: u64,
    payload: &ExecutionPayloadHeader,
    finalized: &BeaconBlockHeader,
    branch: &[[u8; 32]],
) -> Result<(), MosooError> {
    let gindex = crypto::execution_proof_gindex(chain_id, finalized.slot);
    let leaf = if gindex == crypto::EXECUTION_BLOCK_HASH_GINDEX_GLOAS {
        payload.block_hash
    } else {
        crypto::hash_tree_root_execution_payload_header(payload)?
    };
    let root = crypto::compute_branch_root_checked(leaf, branch, gindex)?;

    if root != finalized.body_root {
        return Err(MosooError::ExecutionPayloadBranchInvalid);
    }
    Ok(())
}
