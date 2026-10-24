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
    #[serde(default)]
    pub historical_execution_proof: Option<HistoricalHeaderProof>,
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
    // Guard: chain_id must be a supported Ethereum network or configured with explicit NetworkConfig
    if !crypto::is_supported_chain_or_configured(args.chain_id, args.network_config.as_ref()) {
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
        instance_id: args.instance_id,
        chain_id: args.chain_id,
        current_header_hash: header_hash,
        current_state_root: args.bootstrap_header.state_root,
        current_slot: args.bootstrap_header.slot,
        current_sync_committee: args.current_sync_committee,
        next_sync_committee: args.initial_next_committee,
        bootstrap_slot: args.bootstrap_header.slot,
        bootstrap_header_hash: header_hash,
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
        network_config: args.network_config,
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
    //    subjectivity operational window (14–30 days) up to the consensus safety bound (1,728,000 slots / ~240 days).
    // 2. Incremental updates cannot jump beyond 1,728,000 slots to prevent long-range consensus forks.
    const WEAK_SUBJECTIVITY_WINDOW_SLOTS: u64 = 1_728_000;
    if update.finalized_header.slot > instance.current_slot + WEAK_SUBJECTIVITY_WINDOW_SLOTS {
        return Err(MosooError::WeakSubjectivityExpired {
            update_slot: update.finalized_header.slot,
            current_slot: instance.current_slot,
        });
    }

    // Period boundary and sync committee selection (Ethereum Altair Light Client Sync Protocol).
    let store_period = crate::types::compute_sync_committee_period(instance.current_slot);
    let sig_period = crate::types::compute_sync_committee_period(update.signature_slot);
    let fin_period = crate::types::compute_sync_committee_period(update.finalized_header.slot);

    // Determine the signing committee that created this aggregate signature.
    let signing_committee = if sig_period == store_period {
        &instance.current_sync_committee
    } else if sig_period == store_period + 1 {
        instance
            .next_sync_committee
            .as_ref()
            .ok_or(MosooError::MissingCommitteeBranch)?
    } else if sig_period > store_period + 1 {
        return Err(MosooError::SyncCommitteePeriodSkip {
            sig_period,
            current_period: store_period,
        });
    } else {
        return Err(MosooError::StaleUpdate {
            update_slot: update.signature_slot,
            current_slot: instance.current_slot,
        });
    };

    // Period consistency: finalized header cannot jump beyond next period without an authenticated handoff.
    if fin_period == store_period + 1 && instance.next_sync_committee.is_none() {
        return Err(MosooError::MissingCommitteeBranch);
    }
    if fin_period > store_period + 1 {
        return Err(MosooError::SyncCommitteePeriodSkip {
            sig_period: fin_period,
            current_period: store_period,
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

    // Aggregate the participating validators' public keys using the authenticated signing committee.
    let agg_pubkey_bytes = crypto::aggregate_participating_pubkeys(
        signing_committee,
        &update.sync_aggregate.sync_committee_bits,
    )?;

    // Compute hash_to_G2(signing_root) — the most expensive step in Begin.
    let msg_g2 = crypto::blst_hash_to_g2(&signing_root);

    let job = JobAccount {
        instance_id: instance.instance_id,
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

    // Cross-stage provenance and instance binding checks (chain ID and unique instance ID)
    if job.instance_chain_id != args.instance.chain_id
        || job.instance_id != args.instance.instance_id
    {
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

    // Cross-stage provenance and instance binding checks (chain ID and unique instance ID)
    if job.instance_chain_id != instance.chain_id || job.instance_id != instance.instance_id {
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
    // Under the Ethereum Altair Light Client Sync Protocol, the active sync committee
    // rotates if and only if the finalized header crosses into the next sync committee period.
    // Tying rotation strictly to `fin_period > store_period` guarantees that `instance.current_slot`
    // and `instance.current_sync_committee` remain synchronized across arbitrary update boundaries.
    let store_period = crate::types::compute_sync_committee_period(instance.current_slot);
    let fin_period = crate::types::compute_sync_committee_period(update.finalized_header.slot);

    if fin_period > store_period {
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

    // Execution Roots Authentication & Binding:
    // In Gloas ePBS (generalized index 2856), the beacon block body commits only to payload_header.block_hash.
    // The state_root and receipts_root MUST be derived from the verified execution_rlp header.
    let (execution_block_hash, execution_state_root, receipts_root) =
        verify_execution_roots_binding(
            instance.chain_id,
            update.finalized_header.slot,
            payload_header,
            update.execution_rlp.as_deref(),
        )?;

    // Update instance head, state root anchor, and authenticated execution roots.
    instance.current_header_hash = crypto::hash_tree_root_beacon_header(&update.finalized_header);
    instance.current_state_root = update.finalized_header.state_root;
    instance.current_slot = update.finalized_header.slot;
    instance.current_execution_block_hash = execution_block_hash;
    instance.current_execution_state_root = execution_state_root;
    instance.current_receipts_root = receipts_root;

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
    // 0. Instance Authentication & Authenticated Account Binding:
    // A caller cannot supply an unauthenticated, uninitialized, or fabricated InstanceAccount.
    if !args.instance.initialized {
        return Err(MosooError::NotInitialized);
    }
    if args.instance.bootstrap_slot == 0 || args.instance.bootstrap_header_hash == [0u8; 32] {
        return Err(MosooError::InvalidBootstrap(
            "instance contains unauthenticated bootstrap parameters".into(),
        ));
    }
    if args.instance.current_sync_committee.pubkeys.len() != 512 {
        return Err(MosooError::Internal(
            "instance sync committee must contain exactly 512 validator keys".into(),
        ));
    }
    if args.instance.current_slot < args.instance.bootstrap_slot {
        return Err(MosooError::StaleUpdate {
            update_slot: args.instance.current_slot,
            current_slot: args.instance.bootstrap_slot,
        });
    }

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
    // When proving against the latest finalized block, the header's beacon root and all execution roots
    // MUST match the instance's active authenticated roots committed by handle_finish_update.
    if args.header.slot == args.instance.current_slot {
        if args.header.beacon_block_root != args.instance.current_header_hash {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        // Fail-closed verification: To attest state at current_slot, the instance MUST have
        // authenticated non-zero execution roots. Zero is NEVER a bypass or skip signal!
        if args.instance.current_execution_state_root == [0u8; 32]
            || args.header.execution_state_root != args.instance.current_execution_state_root
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        if args.instance.current_receipts_root == [0u8; 32]
            || args.header.receipts_root != args.instance.current_receipts_root
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        if args.instance.current_execution_block_hash == [0u8; 32]
            || args.header.execution_block_hash != args.instance.current_execution_block_hash
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
    } else {
        // Historical block root authentication:
        // In Ethereum consensus specs, BeaconState contains `block_roots: Vector[Root, 8192]`.
        // Guard: block_roots is a cyclic ring buffer of 8,192 slots. Proving blocks older than
        // 8,192 slots requires historical_summaries / historical_roots.
        const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
        let delta = args.instance.current_slot.saturating_sub(args.header.slot);
        if delta == 0 || delta > SLOTS_PER_HISTORICAL_ROOT {
            return Err(MosooError::HistoricalSummariesWindowExceeded {
                target_slot: args.header.slot,
                current_slot: args.instance.current_slot,
            });
        }

        // Fail-closed cryptographic provenance: Historical execution roots MUST be independently
        // authenticated against the historical beacon block body. A caller CANNOT supply arbitrary
        // execution roots with a genuine beacon block root!
        let hist_proof = args
            .historical_execution_proof
            .as_ref()
            .ok_or(MosooError::HistoricalExecutionRootUnauthenticated)?;

        // 1. Verify beacon block header matches the claimed beacon_block_root
        if hist_proof.beacon_header.slot != args.header.slot {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        let computed_beacon_root = crypto::hash_tree_root_beacon_header(&hist_proof.beacon_header);
        if computed_beacon_root != args.header.beacon_block_root {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }

        // 2. Verify beacon block root is anchored in instance.current_state_root (block_roots ring buffer)
        let gindex = crypto::historical_block_roots_gindex(
            args.instance.chain_id,
            args.instance.current_slot,
            args.header.slot,
        );
        let branch = args
            .header_history_branch
            .as_ref()
            .unwrap_or(&hist_proof.block_roots_branch);
        let computed_state_root =
            crypto::compute_branch_root_checked(args.header.beacon_block_root, branch, gindex)?;
        if computed_state_root != args.instance.current_state_root {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }

        // 3. Verify execution payload header is anchored in beacon_header.body_root
        verify_execution_payload_branch(
            args.instance.chain_id,
            &hist_proof.execution_payload_header,
            &hist_proof.beacon_header,
            &hist_proof.execution_branch,
        )?;

        // 4. Derive authentic execution roots from verified payload header
        let (auth_exec_hash, auth_state_root, auth_receipts_root) = verify_execution_roots_binding(
            args.instance.chain_id,
            args.header.slot,
            &hist_proof.execution_payload_header,
            hist_proof.execution_rlp.as_deref(),
        )?;

        // 5. Strict equality check: the caller's HeaderRecord execution roots MUST match the authenticated roots!
        if args.header.execution_state_root != auth_state_root
            || args.header.receipts_root != auth_receipts_root
            || args.header.execution_block_hash != auth_exec_hash
            || args.header.execution_state_root == [0u8; 32]
            || args.header.receipts_root == [0u8; 32]
            || args.header.execution_block_hash == [0u8; 32]
        {
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

/// Cryptographically verify and bind execution roots.
///
/// In Gloas ePBS (generalized index 2856), the beacon block body commits only to `payload_header.block_hash`.
/// The `state_root` and `receipts_root` MUST be derived from the authentic RLP execution block header
/// whose keccak256 hash matches `payload_header.block_hash`.
///
/// If `payload_header` contains conflicting non-zero roots, or if `execution_rlp` is missing,
/// this function fails closed with `ExecutionPayloadBranchInvalid` or `GloasExecutionRlpMismatch`.
#[allow(clippy::type_complexity)]
pub fn verify_execution_roots_binding(
    chain_id: u64,
    slot: u64,
    payload_header: &ExecutionPayloadHeader,
    execution_rlp: Option<&[u8]>,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), MosooError> {
    let gindex = crypto::execution_proof_gindex(chain_id, slot);
    if gindex == crypto::EXECUTION_BLOCK_HASH_GINDEX_GLOAS {
        let rlp = execution_rlp.ok_or(MosooError::GloasExecutionRlpMismatch)?;
        let (derived_state_root, derived_receipts_root, _block_num) =
            crate::inclusion::execution_header_roots(&payload_header.block_hash, rlp)?;

        // Fail-closed invariant: if caller-supplied payload_header contains conflicting roots, reject.
        if payload_header.state_root != [0u8; 32] && payload_header.state_root != derived_state_root
        {
            return Err(MosooError::ExecutionPayloadBranchInvalid);
        }
        if payload_header.receipts_root != [0u8; 32]
            && payload_header.receipts_root != derived_receipts_root
        {
            return Err(MosooError::ExecutionPayloadBranchInvalid);
        }

        Ok((
            payload_header.block_hash,
            derived_state_root,
            derived_receipts_root,
        ))
    } else {
        Ok((
            payload_header.block_hash,
            payload_header.state_root,
            payload_header.receipts_root,
        ))
    }
}

/// Verify provenance and root integrity of a `HeaderRecord` against an authenticated `InstanceAccount`.
///
/// Ensures callers cannot supply fabricated execution roots alongside a genuine beacon block root.
pub fn verify_header_record_provenance(
    instance: &InstanceAccount,
    header: &HeaderRecord,
) -> Result<(), MosooError> {
    if header.chain_id != instance.chain_id {
        return Err(MosooError::DomainSeparationFailed);
    }
    if header.slot > instance.current_slot {
        return Err(MosooError::UnfinalizedHeader {
            header_slot: header.slot,
            current_slot: instance.current_slot,
        });
    }
    if header.slot == instance.current_slot {
        if header.beacon_block_root != instance.current_header_hash {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        if instance.current_execution_state_root == [0u8; 32]
            || header.execution_state_root != instance.current_execution_state_root
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        if instance.current_receipts_root == [0u8; 32]
            || header.receipts_root != instance.current_receipts_root
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
        if instance.current_execution_block_hash == [0u8; 32]
            || header.execution_block_hash != instance.current_execution_block_hash
        {
            return Err(MosooError::UnauthenticatedHeaderRecord);
        }
    } else {
        // Enforce fail-closed invariant for historical slots (header.slot < instance.current_slot):
        // Standalone InstanceAccount does not hold historical execution roots. Complete
        // cryptographic provenance requires HistoricalHeaderProof via verify_historical_header_provenance.
        return Err(MosooError::HistoricalExecutionRootUnauthenticated);
    }
    Ok(())
}

/// Verify cryptographic provenance and execution root authenticity of a historical `HeaderRecord`.
pub fn verify_historical_header_provenance(
    instance: &InstanceAccount,
    header: &HeaderRecord,
    proof: &HistoricalHeaderProof,
) -> Result<(), MosooError> {
    if header.chain_id != instance.chain_id {
        return Err(MosooError::DomainSeparationFailed);
    }
    if header.slot >= instance.current_slot {
        return Err(MosooError::Internal(
            "verify_historical_header_provenance expects historical slot strictly prior to current head".into(),
        ));
    }
    const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
    let delta = instance.current_slot.saturating_sub(header.slot);
    if delta == 0 || delta > SLOTS_PER_HISTORICAL_ROOT {
        return Err(MosooError::HistoricalSummariesWindowExceeded {
            target_slot: header.slot,
            current_slot: instance.current_slot,
        });
    }

    if proof.beacon_header.slot != header.slot {
        return Err(MosooError::UnauthenticatedHeaderRecord);
    }
    let computed_beacon_root = crypto::hash_tree_root_beacon_header(&proof.beacon_header);
    if computed_beacon_root != header.beacon_block_root {
        return Err(MosooError::UnauthenticatedHeaderRecord);
    }

    let gindex = crypto::historical_block_roots_gindex(
        instance.chain_id,
        instance.current_slot,
        header.slot,
    );
    let computed_state_root = crypto::compute_branch_root_checked(
        header.beacon_block_root,
        &proof.block_roots_branch,
        gindex,
    )?;
    if computed_state_root != instance.current_state_root {
        return Err(MosooError::UnauthenticatedHeaderRecord);
    }

    verify_execution_payload_branch(
        instance.chain_id,
        &proof.execution_payload_header,
        &proof.beacon_header,
        &proof.execution_branch,
    )?;

    let (auth_exec_hash, auth_state_root, auth_receipts_root) = verify_execution_roots_binding(
        instance.chain_id,
        header.slot,
        &proof.execution_payload_header,
        proof.execution_rlp.as_deref(),
    )?;

    if header.execution_state_root != auth_state_root
        || header.receipts_root != auth_receipts_root
        || header.execution_block_hash != auth_exec_hash
        || header.execution_state_root == [0u8; 32]
        || header.receipts_root == [0u8; 32]
        || header.execution_block_hash == [0u8; 32]
    {
        return Err(MosooError::UnauthenticatedHeaderRecord);
    }

    Ok(())
}
