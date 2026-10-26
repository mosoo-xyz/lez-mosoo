//! Custom error types for the Mosoo attestation module.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MosooError {
    // Initialization & Bootstrap
    #[error("instance already initialized for chain {chain_id}")]
    AlreadyInitialized { chain_id: u64 },

    #[error("instance not yet initialized")]
    NotInitialized,

    #[error("bootstrap sync committee branch verification failed against checkpoint state root")]
    BootstrapCommitteeBranchInvalid,

    #[error(
        "bootstrap next sync committee branch verification failed against checkpoint state root"
    )]
    BootstrapNextCommitteeBranchInvalid,

    #[error("invalid bootstrap checkpoint: {0}")]
    InvalidBootstrap(String),

    // Quorum & Sync Aggregate Length Validation
    #[error("invalid sync committee bits length: actual {actual}, expected {expected}")]
    InvalidSyncCommitteeBitsLength { actual: usize, expected: usize },

    #[error("invalid sync committee member count: actual {actual}, expected {expected}")]
    InvalidSyncCommitteeLength { actual: usize, expected: usize },

    #[error("invalid sync committee signature length: actual {actual}, expected {expected}")]
    InvalidSyncCommitteeSignatureLength { actual: usize, expected: usize },

    #[error("invalid proof branch depth: actual {actual}, expected {expected}")]
    InvalidProofBranchDepth { actual: usize, expected: usize },

    // Cross-Stage Binding & Job Provenance
    #[error("job instance mismatch: expected chain_id {expected}, got {actual}")]
    JobInstanceMismatch { expected: u64, actual: u64 },

    #[error("job slot mismatch: expected slot {expected}, got {actual}")]
    JobSlotMismatch { expected: u64, actual: u64 },

    #[error("job update digest mismatch: computed {computed:?}, recorded {recorded:?}")]
    JobDigestMismatch {
        computed: [u8; 32],
        recorded: [u8; 32],
    },

    // Consumer settlement binding
    #[error("unauthenticated consumer attester: expected {expected:?}, got {actual:?}")]
    UnauthenticatedAttester {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("claimed amount exceeds verified attestation: claimed {claimed}, verified {verified}")]
    ClaimAmountExceedsVerified { claimed: u128, verified: u128 },

    #[error("predicate condition failed to hold over verified state")]
    PredicateFailed,

    // Schema and length validation
    #[error("invalid logs bloom length: actual {actual}, expected {expected}")]
    InvalidLogsBloomLength { actual: usize, expected: usize },

    #[error("invalid extra data length: actual {actual}, max allowed {max}")]
    InvalidExtraDataLength { actual: usize, max: usize },

    #[error("unsupported log data length: {0}")]
    UnsupportedLogDataLength(usize),

    // Update validation
    #[error("update slot {update_slot} is not newer than current head {current_slot}")]
    StaleUpdate { update_slot: u64, current_slot: u64 },

    #[error("sync committee participation {actual}/512 is below the 2/3 threshold ({required})")]
    InsufficientParticipation { actual: usize, required: usize },

    #[error("BLS aggregate signature verification failed")]
    InvalidSignature,

    // Job state machine
    #[error("job is in stage {actual:?}, expected {expected:?}")]
    WrongJobStage { expected: String, actual: String },

    #[error("miller-loop input is missing from job account")]
    MissingMillerInput,

    #[error("miller-loop output is missing from job account")]
    MissingMillerOutput,

    // Merkle / inclusion proofs
    #[error("invalid Merkle-Patricia trie proof")]
    InvalidTrieProof,

    #[error("account not found in state trie for the given address")]
    AccountNotFound,

    #[error("storage slot not found in account storage trie")]
    StorageSlotNotFound,

    #[error("receipt not found in receipt trie for tx index {0}")]
    ReceiptNotFound(u64),

    #[error("log index {log_index} out of bounds (receipt has {total_logs} logs)")]
    LogIndexOutOfBounds { log_index: usize, total_logs: usize },

    #[error("event emitter address mismatch: expected {expected}, got {actual}")]
    EventEmitterMismatch { expected: String, actual: String },

    #[error("event topic mismatch at index {index}: expected {expected}, got {actual}")]
    EventTopicMismatch {
        index: usize,
        expected: String,
        actual: String,
    },

    #[error("RLP decoding failed: {0}")]
    RlpDecodeFailed(String),

    // Finality and branch proofs
    #[error("finality branch verification failed (depth mismatch or bad root)")]
    FinalityBranchInvalid,

    #[error("sync-committee branch verification failed")]
    SyncCommitteeBranchInvalid,

    #[error("execution payload header is mandatory for post-merge Ethereum updates")]
    MissingExecutionPayload,

    #[error("execution payload Merkle branch is mandatory")]
    MissingExecutionPayloadBranch,

    #[error("execution payload branch verification failed")]
    ExecutionPayloadBranchInvalid,

    #[error(
        "next_sync_committee branch is required for period-boundary updates but was not provided"
    )]
    MissingCommitteeBranch,

    #[error("sync committee period jump / skip not permitted: signature period {sig_period}, current period {current_period}")]
    SyncCommitteePeriodSkip {
        sig_period: u64,
        current_period: u64,
    },

    #[error("Gloas execution RLP header missing or keccak256 hash does not match block hash")]
    GloasExecutionRlpMismatch,

    // Cryptographic state & provenance binding
    #[error("header record is unauthenticated or does not match active instance finalized state")]
    UnauthenticatedHeaderRecord,

    #[error("beacon block root mismatch: expected {expected:?}, actual {actual:?}")]
    HeaderHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("historical execution roots unauthenticated: complete beacon body and execution payload branch proof required")]
    HistoricalExecutionRootUnauthenticated,

    #[error("historical block is older than 8,192 slots ({target_slot} vs {current_slot}); outside active block_roots ring buffer")]
    HistoricalSummariesWindowExceeded { target_slot: u64, current_slot: u64 },

    #[error("header slot {header_slot} exceeds latest finalized consensus slot {current_slot}")]
    UnfinalizedHeader { header_slot: u64, current_slot: u64 },

    #[error("update slot {update_slot} exceeds weak-subjectivity window beyond current slot {current_slot}")]
    WeakSubjectivityExpired { update_slot: u64, current_slot: u64 },

    #[error("unsupported chain ID {0}")]
    UnsupportedChain(u64),

    // Cryptography
    #[error("BLS12-381 public key is invalid: {0}")]
    InvalidPublicKey(String),

    #[error("BLS12-381 public key aggregation failed")]
    AggregationFailed,

    // Chain ID and domain separation
    #[error("chain ID mismatch: statement is for chain {statement_chain}, but instance tracks chain {instance_chain}")]
    ChainIdMismatch {
        statement_chain: u64,
        instance_chain: u64,
    },

    #[error("domain separation check failed")]
    DomainSeparationFailed,

    #[error("unauthorized account or owner: account does not belong to program")]
    UnauthorizedAccount,

    #[error("instance account is unauthenticated or PDA does not match expected address")]
    UnauthenticatedInstance,

    #[error("job account is unauthenticated or PDA does not match expected address")]
    UnauthenticatedJobAccount,

    #[error("job account collision: conflicting update already exists at this job PDA")]
    JobAccountCollision,

    #[error("unconfigured genesis validators root: custom network must provide non-zero genesis_validators_root")]
    UnconfiguredGenesisValidatorsRoot,

    #[error("unauthenticated source instance: zero instance PDA is not permitted")]
    UnauthenticatedSourceInstance,

    #[error(
        "untrusted source instance: statement source_instance_pda does not match trusted instance"
    )]
    UntrustedSourceInstance,

    #[error("persistent storage write failed: {0}")]
    StorageWriteFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}
