// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title MosooLocker
 * @notice Canonical Ethereum Escrow and Settlement contract for the Mosoo Light Client Bridge
 *         connecting Ethereum (Mainnet / Sepolia / Holesky) and the Logos Execution Zone (LEZ).
 *
 * @dev Bridge Trust Model & Security Invariants:
 * 1. Inbound Bridge (Ethereum -> LEZ): 100% Trustless. Verified inside LEZ zkVM/runtime
 *    using Merkle-Patricia Trie proofs against Ethereum consensus sync committee roots (Logos RFP-021).
 * 2. Outbound Bridge (LEZ -> Ethereum): Witness-attested settlement model with multi-layered defense-in-depth:
 *    - Strict EIP-712 structured data and domain separation binding verifyingContract `address(this)`.
 *    - Replay protection via cryptographic `executedBurns[burnId]` nullifier registry.
 *    - Rolling 24-hour daily volume limits (`dailyWithdrawalLimitETH`, `dailyWithdrawalLimitERC20`).
 *    - Mandatory 24-hour timelock delay for large withdrawals (`>= 10 ether`).
 *    - Emergency pause (`pause()`) and Guardian veto (`cancelQueuedWithdrawal()`).
 * 3. Dual-Asset Settlement: Complete support for native ETH (`depositETH`, `unlockETH`) and
 *    ERC-20 tokens (`depositERC20`, `unlockERC20`).
 * 4. Signature Malleability Protection: Enforces strict EIP-2 upper-bound checks on `s` values.
 * 5. Fee-on-Transfer Protection: Uses before/after balance differentials on `depositERC20`.
 * 6. Reentrancy Protection: Custom non-reentrant mutex guarding all state-mutating deposit and unlock paths.
 * 7. Two-Step Ownership: Enforces `transferOwnership` + `acceptOwnership` preventing accidental contract loss.
 */
contract MosooLocker {
    // --- State Variables ---

    address public owner;
    address public pendingOwner;
    address public attesterAuthority;
    address public pendingAttesterAuthority;
    uint256 public authorityTimelockUnlock;
    uint256 private constant AUTHORITY_CHANGE_DELAY = 1 days;

    /// @notice Multi-signer attester committee membership and M-of-N threshold quorum
    mapping(address => bool) public isAttester;
    uint256 public attesterCount;
    uint256 public requiredQuorum;

    /// @notice Strict multi-attester threshold requirement for fully commissioned production release
    uint256 private constant MIN_PRODUCTION_QUORUM = 2;

    /// @notice Irreversible latch set once locker reaches production multi-attester commissioning
    bool public productionCommissioned;

    address public guardian;
    bool public paused;

    uint256 public totalLockedETH;
    uint256 public totalUnlockedETH;
    uint64 public depositNonce;

    /// @notice Nullifier registry preventing cross-chain burn replay attacks
    mapping(bytes32 => bool) public executedBurns;

    /// @notice ERC-20 token deposit accounting: token => total locked
    mapping(address => uint256) public totalLockedERC20;

    /// @notice Optional token allowlist to restrict deposits to verified non-rebasing tokens
    bool public tokenAllowlistEnabled;
    mapping(address => bool) public isTokenAllowed;

    /// @notice Migration & isolation switch for legacy V1 withdrawal routes lacking sourceInstance binding (Finding 5)
    bool public legacyRoutesEnabled = false;

    /// @notice Irreversible killswitch permanently retiring legacy V1 withdrawal routes (Finding 4 / P2)
    bool public legacyRoutesPermanentlyDisabled = false;

    // --- Rate Limiting & Timelock Defense-in-Depth ---

    /// @dev Continuous rolling 24-hour window record
    struct WithdrawalRecord {
        uint64 timestamp;
        uint192 amount;
    }

    uint256 private constant ROLLING_WINDOW = 1 days;

    /// @notice Rolling daily withdrawal limit for ETH (0 = disabled/unlimited)
    uint256 public dailyWithdrawalLimitETH;
    /// @notice Rolling daily withdrawal limits for ERC-20 tokens (token => limit)
    mapping(address => uint256) public dailyWithdrawalLimitERC20;

    /// @dev Unified rolling withdrawal history keyed by asset (address(0) = ETH, token = ERC-20)
    mapping(address => WithdrawalRecord[]) private _withdrawalHistory;
    mapping(address => uint256) private _withdrawalHead;
    mapping(address => uint256) private _rollingWithdrawn;

    /// @notice Multi-signer governance timelock (2-day delay for attester/quorum modifications)
    uint256 public constant GOVERNANCE_TIMELOCK_DELAY = 2 days;
    /// @notice Maximum number of expired withdrawal records cleaned up per transaction to guarantee O(1) gas
    uint256 private constant MAX_CLEANUP_BATCH = 32;
    /// @notice Maximum number of records pruned in second-pass cleanup to bound gas on limit contention
    uint256 private constant MAX_PASS2_CLEANUP_BATCH = 128;

    uint256 private pendingQuorum;
    uint256 public quorumTimelockUnlock;
    address private pendingAddAttester;
    uint256 public addAttesterTimelockUnlock;
    address private pendingRemoveAttester;
    uint256 private removeAttesterTimelockUnlock;
    address public pendingGuardian;
    uint256 public guardianTimelockUnlock;

    /// @notice Timelocked rate-limit administration (2-day timelock delay)
    uint256 private pendingDailyLimitETH;
    uint256 public dailyLimitETHTimelockUnlock;
    bool private hasPendingDailyLimitETH;

    mapping(address => uint256) private pendingDailyLimitERC20;
    mapping(address => uint256) private dailyLimitERC20TimelockUnlock;
    mapping(address => bool) private hasPendingDailyLimitERC20;

    /// @notice Timelocked security & privacy relaxation governance (2-day timelock + guardian cancellable)
    uint256 private disableAllowlistTimelockUnlock;
    uint256 public disableShieldedOnlyTimelockUnlock;
    uint256 private disableStrictDenomTimelockUnlock;
    address private pendingTokenAllowedAddr;
    bool private pendingTokenAllowedFlag;
    uint256 private tokenAllowedTimelockUnlock;
    uint256 private pendingDenomAmount;
    bool private pendingDenomAllowed;
    uint256 private denomTimelockUnlock;

    /// @notice Large withdrawal threshold requiring mandatory timelock delay
    uint256 private constant LARGE_WITHDRAWAL_THRESHOLD_ETH = 10 ether;
    uint256 private constant LARGE_WITHDRAWAL_DELAY = 1 days;

    /// @notice Per-token large withdrawal threshold requiring mandatory 24h timelock delay (0 = disabled).
    mapping(address => uint256) public largeWithdrawalThresholdERC20;
    mapping(address => uint256) private pendingLargeThresholdERC20;
    mapping(address => uint256) private largeThresholdERC20TimelockUnlock;
    mapping(address => bool) private hasPendingLargeThresholdERC20;

    /// @notice Queued large withdrawals: burnId => executableTimestamp
    mapping(bytes32 => uint256) public queuedWithdrawalUnlockTime;
    /// @notice Bound payload hash for queued withdrawals (prevents parameter swapping post-queue)
    mapping(bytes32 => bytes32) public queuedWithdrawalPayloadHash;

    /// @notice Permanently cancelled burns (cannot be re-queued or unlocked by anyone)
    mapping(bytes32 => bool) public cancelledBurns;

    // --- EIP-712 Domain Separation ---
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public constant BURN_ETH_TYPEHASH = keccak256(
        "BurnETH(bytes32 burnId,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    bytes32 private constant BURN_ERC20_TYPEHASH = keccak256(
        "BurnERC20(bytes32 burnId,address token,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    // --- V2 Cross-Instance Domain-Separated Typehashes ---
    bytes32 public constant BURN_ETH_V2_TYPEHASH = keccak256(
        "BurnETHV2(bytes32 burnId,bytes32 sourceInstance,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    bytes32 private constant BURN_ERC20_V2_TYPEHASH = keccak256(
        "BurnERC20V2(bytes32 burnId,bytes32 sourceInstance,address token,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    // --- RFP-022 Shielded Outbound Unlock Typehashes (no lezOwner/burnNonce/lezSlot leaked on L1) ---
    bytes32 public constant SHIELDED_BURN_ETH_TYPEHASH = keccak256(
        "ShieldedBurnETH(bytes32 burnNullifier,bytes32 sourceInstance,address recipient,uint256 amount)"
    );

    bytes32 public constant SHIELDED_BURN_ERC20_TYPEHASH = keccak256(
        "ShieldedBurnERC20(bytes32 burnNullifier,bytes32 sourceInstance,address token,address recipient,uint256 amount)"
    );

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("MosooLocker")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // --- Reentrancy Guard ---
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    // --- RFP-022 Privacy-Preserving Shielded Commitment Pool & Incremental Merkle Tree ---
    uint32 private constant MERKLE_TREE_DEPTH = 20;
    bytes32 private constant EMPTY_LEAF_HASH = keccak256("mosoo_empty_leaf_v1");
    uint32 public nextCommitmentIndex;
    bytes32[20] private _filledSubtrees;
    bytes32 public currentCommitmentRoot;
    mapping(bytes32 => bool) public knownDepositRoots;
    mapping(bytes32 => bool) public commitments;
    bool public shieldedDepositsOnly;
    bool public strictFixedDenominationMode;
    mapping(uint256 => bool) public isStandardDenomination;

    // --- Events ---

    event DepositETH(
        address indexed sender,
        bytes32 indexed lezRecipient,
        uint256 amount,
        uint64 indexed nonce
    );

    event DepositERC20(
        address indexed token,
        address indexed sender,
        bytes32 indexed lezRecipient,
        uint256 amount,
        uint64 nonce
    );

    /// @notice Privacy-preserving RFP-022 deposit commitment event.
    /// @dev Deliberately omits both Ethereum `sender` and target `lezRecipient` so
    ///      no observer can link an Ethereum deposit to its LEZ mint destination.
    event DepositCommitted(
        bytes32 indexed commitment,
        address indexed token,
        uint256 amount,
        uint32 indexed leafIndex,
        bytes32 newRoot,
        uint64 nonce
    );

    event ShieldedDepositsOnlyToggled(bool enabled);
    event StrictDenominationModeToggled(bool enabled);
    event StandardDenominationUpdated(uint256 denomination, bool allowed);

    event UnlockedShieldedETH(
        bytes32 indexed burnNullifier,
        address indexed recipient,
        uint256 amount
    );

    event UnlockedShieldedERC20(
        bytes32 indexed burnNullifier,
        address indexed token,
        address indexed recipient,
        uint256 amount
    );

    event UnlockedETH(
        bytes32 indexed burnId,
        address indexed recipient,
        uint256 amount,
        uint64 lezSlot
    );

    event UnlockedERC20(
        bytes32 indexed burnId,
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint64 lezSlot
    );

    event AttesterAuthorityUpdated(address indexed oldAuthority, address indexed newAuthority);
    event AttesterAuthorityChangeProposed(address indexed currentAuthority, address indexed proposedAuthority, uint256 unlockTimestamp);
    event AttesterAdded(address indexed attester);
    event AttesterRemoved(address indexed attester);
    event QuorumUpdated(uint256 oldQuorum, uint256 newQuorum);
    event GuardianUpdated(address indexed previousGuardian, address indexed newGuardian);
    event GuardianChangeProposed(address indexed currentGuardian, address indexed proposedGuardian, uint256 unlockTimestamp);
    event PausedStateChanged(bool isPaused);
    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TokenAllowlistToggled(bool enabled);
    event TokenAllowedStatusUpdated(address indexed token, bool allowed);
    event WithdrawalQueued(bytes32 indexed burnId, address indexed recipient, uint256 amount, uint256 unlockTimestamp);
    event QueuedWithdrawalCancelled(bytes32 indexed burnId, address indexed cancelledBy);
    event BurnPermanentlyCancelled(bytes32 indexed burnId, address indexed cancelledBy);
    event DailyWithdrawalLimitUpdatedETH(uint256 oldLimit, uint256 newLimit);
    event DailyWithdrawalLimitUpdatedERC20(address indexed token, uint256 oldLimit, uint256 newLimit);
    event LargeWithdrawalThresholdERC20Updated(address indexed token, uint256 oldThreshold, uint256 newThreshold);
    event LargeWithdrawalThresholdERC20Proposed(address indexed token, uint256 currentThreshold, uint256 proposedThreshold, uint256 unlockTimestamp);
    event QuorumChangeProposed(uint256 currentQuorum, uint256 proposedQuorum, uint256 unlockTimestamp);
    event AttesterAddProposed(address indexed proposedAttester, uint256 unlockTimestamp);
    event AttesterRemoveProposed(address indexed proposedAttester, uint256 unlockTimestamp);
    event DailyLimitETHChangeProposed(uint256 currentLimit, uint256 proposedLimit, uint256 unlockTimestamp);
    event DailyLimitERC20ChangeProposed(address indexed token, uint256 currentLimit, uint256 proposedLimit, uint256 unlockTimestamp);
    event PendingGovernanceCancelled(string action, address indexed cancelledBy);
    event LegacyRoutesToggled(bool enabled);
    event LegacyRoutesPermanentlyRetired();

    // --- Errors ---

    error ZeroAmount();
    error ZeroAddress();
    error ContractPaused();
    error Unauthorized();
    error ReentrancyGuardReentrantCall();
    error BurnAlreadyExecuted();
    error BurnCancelled();
    error InvalidBurnProof();
    error InvalidSourceInstance();
    error InsufficientLockedETH();
    error InsufficientLockedERC20();
    error ETHTransferFailed();
    error ERC20TransferFailed();
    error TokenNotAllowed();
    error BalanceQueryFailed();
    error AuthorityTimelockActive(uint256 currentTime, uint256 unlockTime);
    error NoPendingAuthority();
    error DailyLimitExceeded(uint256 requested, uint256 available);
    error LargeWithdrawalPending(uint256 unlockTimestamp);
    error NoQueuedWithdrawal();
    error InvalidQuorum();
    error DuplicateOrUnorderedAttesterSignature();
    error AttesterAlreadyExists();
    error AlreadyCommissioned();
    error AttesterNotFound();
    error GovernanceTimelockActive(uint256 currentTime, uint256 unlockTime);
    error NoPendingGovernanceAction();
    error DirectGovernanceDeprecated();
    error InvalidGuardian();
    error GuardianMustNotBeOwner();
    error LegacyRoutesDisabled();
    error LegacyRoutesArePermanentlyRetired();
    error AmountExceedsUint192();
    error ZeroCommitment();
    error CommitmentAlreadyExists();
    error MerkleTreeFull();
    error ShieldedDepositsOnlyActive();
    error InvalidDenomination(uint256 amount);
    error InvalidDailyLimit();
    error DailyLimitNotConfigured();
    error WithdrawalPayloadMismatch();
    error PrivacySettingLocked();

    // --- Modifiers ---

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    modifier whenNotPaused() {
        _checkNotPaused();
        _;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert Unauthorized();
    }

    function _checkNotPaused() internal view {
        if (paused) revert ContractPaused();
    }

    function _nonReentrantBefore() internal {
        if (_status == _ENTERED) revert ReentrancyGuardReentrantCall();
        _status = _ENTERED;
    }

    function _nonReentrantAfter() internal {
        _status = _NOT_ENTERED;
    }

    /// @notice Returns true if the locker has graduated from initial commissioning (attesterCount >= 2 and requiredQuorum >= 2).
    function isCommissioned() public view returns (bool) {
        return productionCommissioned
            || (attesterCount >= MIN_PRODUCTION_QUORUM && requiredQuorum >= MIN_PRODUCTION_QUORUM);
    }

    /**
     * @notice Commission locker to production multi-attester threshold (>= 2 attesters, quorum >= 2).
     * @dev Allows initial bootstrap from 1-of-1 commissioning mode without 2-day timelock delay.
     *      Once commissioned, requiredQuorum can never be lowered below MIN_PRODUCTION_QUORUM and
     *      all subsequent attester additions/removals and quorum changes require full timelock governance.
     * @param additionalAttesters Array of new authorized attester addresses.
     * @param initialQuorum New threshold quorum (must be >= 2 and <= attesterCount).
     */
    function commissionLocker(address[] calldata additionalAttesters, uint256 initialQuorum) external onlyOwner {
        if (isCommissioned()) revert AlreadyCommissioned();
        if (additionalAttesters.length == 0) revert ZeroAmount();
        for (uint256 i = 0; i < additionalAttesters.length; i++) {
            address att = additionalAttesters[i];
            if (att == address(0)) revert ZeroAddress();
            if (isAttester[att]) revert AttesterAlreadyExists();
            isAttester[att] = true;
            attesterCount += 1;
            emit AttesterAdded(att);
        }
        if (initialQuorum < MIN_PRODUCTION_QUORUM || initialQuorum > attesterCount) revert InvalidQuorum();
        uint256 oldQuorum = requiredQuorum;
        requiredQuorum = initialQuorum;
        productionCommissioned = true;
        if (shieldedDepositsOnly) {
            disableShieldedOnlyTimelockUnlock = 0;
        }
        if (strictFixedDenominationMode) {
            disableStrictDenomTimelockUnlock = 0;
        }
        emit QuorumUpdated(oldQuorum, requiredQuorum);
    }

    // --- Constructor ---

    /**
     * @notice Initializes MosooLocker vault and sets initial governance addresses.
     * @dev Note on Governance & Multi-Signer Quorum Threshold:
     *      Initial deployment sets `attesterCount = 1` and `requiredQuorum = 1` for bootstrap commissioning.
     *      For production mainnet operation, the operator executes a 3-step timelocked governance transition:
     *        1. proposeAddAttester(attester2) -> wait 2 days -> executeAddAttester()
     *        2. proposeAddAttester(attester3) -> wait 2 days -> executeAddAttester()
     *        3. proposeQuorum(2)              -> wait 2 days -> executeQuorum()
     *      Direct un-timelocked calls to addAttester/setQuorum are permanently deprecated (revert with DirectGovernanceDeprecated)
     *      to prevent single-key administrative takeovers.
     * @param _attesterAuthority The initial bootstrap attester authority address.
     * @param _guardian The independent emergency guardian address (must NOT be owner).
     */
    constructor(address _attesterAuthority, address _guardian) {
        if (_attesterAuthority == address(0)) revert ZeroAddress();
        if (_guardian == address(0)) revert InvalidGuardian();
        if (_guardian == msg.sender) revert GuardianMustNotBeOwner();
        owner = msg.sender;
        guardian = _guardian;
        attesterAuthority = _attesterAuthority;
        isAttester[_attesterAuthority] = true;
        attesterCount = 1;
        requiredQuorum = 1;
        tokenAllowlistEnabled = true; // Enabled by default for strict production safety
        dailyWithdrawalLimitETH = 100 ether; // Safe default daily withdrawal rate limit (Finding M-03/M-05 hardening)

        // Finding M-05 hardening: Configure explicit default daily caps for registered canonical testnet tokens
        address sepoliaUSDC = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
        address sepoliaUSDT = 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06;
        isTokenAllowed[sepoliaUSDC] = true;
        isTokenAllowed[sepoliaUSDT] = true;
        dailyWithdrawalLimitERC20[sepoliaUSDC] = 50_000 * 10**6; // 50,000 USDC per 24h
        dailyWithdrawalLimitERC20[sepoliaUSDT] = 50_000 * 10**6; // 50,000 USDT per 24h
        largeWithdrawalThresholdERC20[sepoliaUSDC] = 10_000 * 10**6; // 10,000 USDC mandatory 24h queue
        largeWithdrawalThresholdERC20[sepoliaUSDT] = 10_000 * 10**6; // 10,000 USDT mandatory 24h queue

        // Initialize Depth-20 incremental commitment Merkle tree zeros (RFP-022 shielded pool)
        bytes32 currentZero = EMPTY_LEAF_HASH;
        for (uint32 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            _filledSubtrees[i] = currentZero;
            currentZero = _hashPair(currentZero, currentZero);
        }
        currentCommitmentRoot = currentZero;
        knownDepositRoots[currentZero] = true;

        // Pre-register standard fixed denominations for RFP-022 amount-uniformity pools
        isStandardDenomination[0.01 ether] = true;
        isStandardDenomination[0.1 ether] = true;
        isStandardDenomination[1 ether] = true;
        isStandardDenomination[10 ether] = true;

        _status = _NOT_ENTERED;
        emit OwnershipTransferred(address(0), msg.sender);
        emit GuardianUpdated(address(0), guardian);
        emit AttesterAuthorityUpdated(address(0), _attesterAuthority);
        emit AttesterAdded(_attesterAuthority);
        emit QuorumUpdated(0, 1);
        emit TokenAllowlistToggled(true);
        emit DailyWithdrawalLimitUpdatedETH(0, 100 ether);
        emit DailyWithdrawalLimitUpdatedERC20(sepoliaUSDC, 0, 50_000 * 10**6);
        emit DailyWithdrawalLimitUpdatedERC20(sepoliaUSDT, 0, 50_000 * 10**6);
        emit LargeWithdrawalThresholdERC20Updated(sepoliaUSDC, 0, 10_000 * 10**6);
        emit LargeWithdrawalThresholdERC20Updated(sepoliaUSDT, 0, 10_000 * 10**6);
    }

    // --- Deposit Functions (ETH -> LEZ) ---

    /**
     * @notice Deposit native ETH into the bridge vault for minting mETH on Logos Execution Zone.
     * @param lezRecipient The 32-byte Base58/PDA account identifier of the recipient on LEZ.
     * @return nonce The deposit nonce used to track this specific deposit transaction.
     */
    function depositETH(bytes32 lezRecipient)
        external
        payable
        whenNotPaused
        nonReentrant
        returns (uint64 nonce)
    {
        if (shieldedDepositsOnly) revert ShieldedDepositsOnlyActive();
        if (msg.value == 0) revert ZeroAmount();
        if (lezRecipient == bytes32(0)) revert ZeroAddress();

        depositNonce += 1;
        nonce = depositNonce;
        totalLockedETH += msg.value;

        emit DepositETH(msg.sender, lezRecipient, msg.value, nonce);
    }

    /**
     * @notice Deposit native ETH privately into the RFP-022 shielded commitment pool.
     * @dev No `lezRecipient` or depositor identity is emitted on Ethereum; the user claims
     *      on LEZ against an attested DepositCommitted receipt log or commitment Merkle root.
     * @param commitment Domain-separated commitment `sha256("mosoo_shielded_deposit_v1" || ...)` or keccak commitment.
     * @return leafIndex Index in the Depth-20 incremental Merkle tree.
     * @return newRoot Updated incremental commitment tree root.
     */
    function depositShieldedETH(bytes32 commitment)
        external
        payable
        whenNotPaused
        nonReentrant
        returns (uint32 leafIndex, bytes32 newRoot)
    {
        if (msg.value == 0) revert ZeroAmount();
        if (commitment == bytes32(0)) revert ZeroCommitment();
        if (strictFixedDenominationMode && !isStandardDenomination[msg.value]) {
            revert InvalidDenomination(msg.value);
        }

        depositNonce += 1;
        uint64 nonce = depositNonce;
        totalLockedETH += msg.value;

        (leafIndex, newRoot) = _insertCommitment(commitment);

        emit DepositCommitted(commitment, address(0), msg.value, leafIndex, newRoot, nonce);
    }

    /**
     * @notice Deposit standard ERC-20 tokens into the bridge vault.
     * @dev Hardened against fee-on-transfer tokens using balance differential checks.
     * @param token The ERC-20 contract address on Ethereum.
     * @param amount The token amount to deposit.
     * @param lezRecipient The 32-byte recipient identifier on LEZ.
     * @return nonce The deposit nonce.
     */
    function depositERC20(address token, uint256 amount, bytes32 lezRecipient)
        external
        whenNotPaused
        nonReentrant
        returns (uint64 nonce)
    {
        if (shieldedDepositsOnly) revert ShieldedDepositsOnlyActive();
        if (lezRecipient == bytes32(0)) revert ZeroAddress();
        uint256 actualAmount = _pullERC20Deposit(token, amount);

        depositNonce += 1;
        nonce = depositNonce;
        totalLockedERC20[token] += actualAmount;

        emit DepositERC20(token, msg.sender, lezRecipient, actualAmount, nonce);
    }

    /**
     * @notice Deposit standard ERC-20 tokens privately into the RFP-022 shielded commitment pool.
     * @dev Uses before/after balance differential for fee-on-transfer safety and emits zero `lezRecipient` data.
     * @param token The ERC-20 contract address on Ethereum.
     * @param amount The token amount to deposit.
     * @param commitment Shielded deposit commitment (non-zero, unique).
     * @return leafIndex Index in the Depth-20 incremental Merkle tree.
     * @return newRoot Updated incremental commitment tree root.
     */
    function depositShieldedERC20(address token, uint256 amount, bytes32 commitment)
        external
        whenNotPaused
        nonReentrant
        returns (uint32 leafIndex, bytes32 newRoot)
    {
        if (commitment == bytes32(0)) revert ZeroCommitment();
        uint256 actualAmount = _pullERC20Deposit(token, amount);
        if (strictFixedDenominationMode && !isStandardDenomination[actualAmount]) {
            revert InvalidDenomination(actualAmount);
        }

        depositNonce += 1;
        uint64 nonce = depositNonce;
        totalLockedERC20[token] += actualAmount;

        (leafIndex, newRoot) = _insertCommitment(commitment);

        emit DepositCommitted(commitment, token, actualAmount, leafIndex, newRoot, nonce);
    }

    function _pullERC20Deposit(address token, uint256 amount) internal returns (uint256 actualAmount) {
        if (amount == 0) revert ZeroAmount();
        if (token == address(0)) revert ZeroAddress();
        if (token.code.length == 0) revert ZeroAddress();
        if (tokenAllowlistEnabled && !isTokenAllowed[token]) revert TokenNotAllowed();

        uint256 balanceBefore = _getTokenBalance(token, address(this));
        _safeTransferFrom(token, msg.sender, address(this), amount);
        actualAmount = _getTokenBalance(token, address(this)) - balanceBefore;
        if (actualAmount == 0) revert ZeroAmount();
    }

    // --- Incremental Commitment Merkle Tree Helpers (RFP-022 Privacy Pool) ---

    function computeCommitmentPair(bytes32 left, bytes32 right) public pure returns (bytes32) {
        return _hashPair(left, right);
    }

    function emptyHashAtLevel(uint32 level) public pure returns (bytes32) {
        bytes32 zeroHash = EMPTY_LEAF_HASH;
        for (uint32 i = 0; i < level; i++) {
            zeroHash = _hashPair(zeroHash, zeroHash);
        }
        return zeroHash;
    }

    function verifyCommitmentInclusion(
        bytes32 commitment,
        uint32 leafIndex,
        bytes32[20] calldata siblings,
        bytes32 root
    ) external view returns (bool) {
        if (commitment == bytes32(0) || !knownDepositRoots[root]) {
            return false;
        }
        uint32 currentIndex = leafIndex;
        bytes32 currentHash = commitment;
        for (uint32 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                currentHash = _hashPair(currentHash, siblings[i]);
            } else {
                currentHash = _hashPair(siblings[i], currentHash);
            }
            currentIndex /= 2;
        }
        return currentHash == root;
    }

    function _hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("mosoo_merkle_v1", left, right));
    }

    function _insertCommitment(bytes32 commitment)
        internal
        returns (uint32 leafIndex, bytes32 newRoot)
    {
        if (commitments[commitment]) revert CommitmentAlreadyExists();
        leafIndex = nextCommitmentIndex;
        if (leafIndex >= (uint32(1) << MERKLE_TREE_DEPTH)) revert MerkleTreeFull();

        commitments[commitment] = true;
        nextCommitmentIndex = leafIndex + 1;

        uint32 currentIndex = leafIndex;
        bytes32 currentHash = commitment;
        bytes32 zeroHash = EMPTY_LEAF_HASH;

        for (uint32 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                _filledSubtrees[i] = currentHash;
                currentHash = _hashPair(currentHash, zeroHash);
            } else {
                currentHash = _hashPair(_filledSubtrees[i], currentHash);
            }
            currentIndex /= 2;
            zeroHash = _hashPair(zeroHash, zeroHash);
        }

        currentCommitmentRoot = currentHash;
        knownDepositRoots[currentHash] = true;
        newRoot = currentHash;
    }

    // --- Unlock Functions (LEZ -> ETH) ---

    /**
     * @notice Release locked native ETH back to an Ethereum address upon verifiable burn on LEZ.
     * @dev Outbound settlement verifies EIP-712 signature from authorized attesterAuthority.
     *      Hardened with rolling daily withdrawal volume caps and mandatory 24h timelock queue for amounts >= 10 ETH.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param amount The amount of ETH (in wei) to unlock.
     * @param recipient The Ethereum recipient address receiving the unlocked ETH.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param attestationSignature Cryptographic signature from the attester authority (EIP-712 witness attestation).
     */
    function unlockETH(
        bytes32 burnId,
        uint256 amount,
        address payable recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes calldata attestationSignature
    ) external whenNotPaused nonReentrant {
        bytes[] memory empty;
        _unlockETHCommon(burnId, bytes32(0), false, amount, recipient, lezOwner, burnNonce, lezSlot, false, attestationSignature, empty);
    }

    /**
     * @notice Release locked ERC-20 tokens back to an Ethereum address upon verifiable burn on LEZ.
     * @dev Outbound settlement verifies EIP-712 signature from authorized attesterAuthority with daily volume limits.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param token The ERC-20 token contract address.
     * @param amount The token amount to unlock.
     * @param recipient The Ethereum recipient address.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param attestationSignature Cryptographic signature from the attester authority.
     */
    function unlockERC20(
        bytes32 burnId,
        address token,
        uint256 amount,
        address recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes calldata attestationSignature
    ) external whenNotPaused nonReentrant {
        bytes[] memory empty;
        _unlockERC20Common(burnId, bytes32(0), false, token, amount, recipient, lezOwner, burnNonce, lezSlot, false, attestationSignature, empty);
    }

    /**
     * @notice Release locked native ETH back to an Ethereum recipient with cross-instance domain separation.
     * @dev Strictly binds sourceInstance (LEZ light-client instance PDA) into canonical burnId and EIP-712 structured data.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param sourceInstance The 32-byte PDA/identifier of the source light-client instance on LEZ.
     * @param amount The ETH amount to unlock in wei.
     * @param recipient The Ethereum recipient address.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param attestationSignature Cryptographic signature from the attester authority.
     */
    function unlockETHWithInstance(
        bytes32 burnId,
        bytes32 sourceInstance,
        uint256 amount,
        address payable recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes calldata attestationSignature
    ) external whenNotPaused nonReentrant {
        bytes[] memory empty;
        _unlockETHCommon(burnId, sourceInstance, true, amount, recipient, lezOwner, burnNonce, lezSlot, false, attestationSignature, empty);
    }

    /**
     * @notice Release locked ERC-20 tokens back to an Ethereum address with cross-instance domain separation.
     * @dev Strictly binds sourceInstance into canonical burnId and EIP-712 structured data.
     */
    function unlockERC20WithInstance(
        bytes32 burnId,
        bytes32 sourceInstance,
        address token,
        uint256 amount,
        address recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes calldata attestationSignature
    ) external whenNotPaused nonReentrant {
        bytes[] memory empty;
        _unlockERC20Common(burnId, sourceInstance, true, token, amount, recipient, lezOwner, burnNonce, lezSlot, false, attestationSignature, empty);
    }

    /**
     * @notice Release locked native ETH back to an Ethereum recipient with M-of-N multi-signer committee attestation.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param recipient The Ethereum recipient address.
     * @param amount The ETH amount to unlock in wei.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param signatures Strictly ascending array of distinct attester EIP-712 signatures.
     */
    
    /**
     * @notice Release locked native ETH back to an Ethereum address with multi-signer threshold quorum AND cross-instance domain separation.
     * @dev Strictly binds sourceInstance into canonical V2 burnId and EIP-712 structured data with M-of-N threshold quorum.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param sourceInstance The unique 32-byte instance ID of the LEZ light-client instance.
     * @param amount The ETH amount to unlock in wei.
     * @param recipient The Ethereum recipient address.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param signatures Strictly ascending array of distinct attester EIP-712 signatures.
     */
    function unlockETHWithInstanceAndQuorum(
        bytes32 burnId,
        bytes32 sourceInstance,
        uint256 amount,
        address payable recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        _unlockETHCommon(burnId, sourceInstance, true, amount, recipient, lezOwner, burnNonce, lezSlot, true, "", signatures);
    }

    /**
     * @notice Release locked ERC-20 tokens back to an Ethereum address with multi-signer threshold quorum AND cross-instance domain separation.
     * @dev Strictly binds sourceInstance into canonical V2 ERC-20 burnId and EIP-712 structured data with M-of-N threshold quorum.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param sourceInstance The unique 32-byte instance ID of the LEZ light-client instance.
     * @param token The ERC-20 token contract address.
     * @param amount The token amount to unlock.
     * @param recipient The Ethereum recipient address.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param signatures Strictly ascending array of distinct attester EIP-712 signatures.
     */
    function unlockERC20WithInstanceAndQuorum(
        bytes32 burnId,
        bytes32 sourceInstance,
        address token,
        uint256 amount,
        address recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        _unlockERC20Common(burnId, sourceInstance, true, token, amount, recipient, lezOwner, burnNonce, lezSlot, true, "", signatures);
    }

    /**
     * @notice Release locked native ETH privately without revealing LEZ burner identity, burnNonce, or lezSlot on L1 (RFP-022).
     * @dev Binds only the opaque `burnNullifier`, `sourceInstance`, `recipient`, and `amount` under EIP-712 quorum verification.
     */
    function unlockShieldedETH(
        bytes32 burnNullifier,
        bytes32 sourceInstance,
        uint256 amount,
        address payable recipient,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        if (burnNullifier == bytes32(0)) revert InvalidBurnProof();
        if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        _validateETHUnlock(burnNullifier, amount, recipient);

        bytes32 structHash = keccak256(
            abi.encode(
                SHIELDED_BURN_ETH_TYPEHASH,
                burnNullifier,
                sourceInstance,
                recipient,
                amount
            )
        );
        if (!_verifyFlexibleSignatures(structHash, signatures)) {
            revert InvalidBurnProof();
        }

        _settleETHUnlock(burnNullifier, sourceInstance, recipient, amount, 0, true);
    }

    /**
     * @notice Release locked ERC-20 tokens privately without revealing LEZ burner identity, burnNonce, or lezSlot on L1 (RFP-022).
     */
    function unlockShieldedERC20(
        bytes32 burnNullifier,
        bytes32 sourceInstance,
        address token,
        uint256 amount,
        address recipient,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        if (burnNullifier == bytes32(0)) revert InvalidBurnProof();
        if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        _validateERC20Unlock(burnNullifier, token, amount, recipient);

        bytes32 structHash = keccak256(
            abi.encode(
                SHIELDED_BURN_ERC20_TYPEHASH,
                burnNullifier,
                sourceInstance,
                token,
                recipient,
                amount
            )
        );
        if (!_verifyFlexibleSignatures(structHash, signatures)) {
            revert InvalidBurnProof();
        }

        _settleERC20Unlock(burnNullifier, sourceInstance, token, recipient, amount, 0, true);
    }

    function _verifyFlexibleSignatures(
        bytes32 structHash,
        bytes[] calldata signatures
    ) internal view returns (bool) {
        if (signatures.length == 1 && requiredQuorum == 1) {
            return _verifyBurnSignature(structHash, signatures[0]);
        }
        return _verifyQuorumSignatures(structHash, signatures);
    }

    function unlockETHWithQuorum(
        bytes32 burnId,
        address payable recipient,
        uint256 amount,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        _unlockETHCommon(burnId, bytes32(0), false, amount, recipient, lezOwner, burnNonce, lezSlot, true, "", signatures);
    }

    /**
     * @notice Release locked ERC-20 tokens back to an Ethereum recipient with M-of-N multi-signer committee attestation.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param token The ERC-20 token contract address.
     * @param amount The token amount to unlock.
     * @param recipient The Ethereum recipient address.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param signatures Strictly ascending array of distinct attester EIP-712 signatures.
     */
    function unlockERC20WithQuorum(
        bytes32 burnId,
        address token,
        uint256 amount,
        address recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        _unlockERC20Common(burnId, bytes32(0), false, token, amount, recipient, lezOwner, burnNonce, lezSlot, true, "", signatures);
    }

    function _validateETHUnlock(bytes32 burnId, uint256 amount, address recipient) internal view {
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedETH < amount || address(this).balance < amount) revert InsufficientLockedETH();
    }

    function _validateERC20Unlock(bytes32 burnId, address token, uint256 amount, address recipient) internal view {
        if (amount == 0) revert ZeroAmount();
        if (token == address(0) || recipient == address(0)) revert ZeroAddress();
        if (token.code.length == 0) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedERC20[token] < amount) revert InsufficientLockedERC20();
    }

    function _verifyModeSignature(
        bytes32 structHash,
        bool isQuorum,
        bytes memory singleSig,
        bytes[] memory quorumSigs
    ) internal view {
        if (!(isQuorum ? _verifyQuorumSignatures(structHash, quorumSigs) : _verifyBurnSignature(structHash, singleSig))) {
            revert InvalidBurnProof();
        }
    }

    function _unlockETHCommon(
        bytes32 burnId,
        bytes32 sourceInstance,
        bool isV2,
        uint256 amount,
        address payable recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bool isQuorum,
        bytes memory singleSig,
        bytes[] memory quorumSigs
    ) internal {
        if (isV2) {
            if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        } else if (!legacyRoutesEnabled || (!isQuorum && isCommissioned())) {
            revert LegacyRoutesDisabled();
        }
        _validateETHUnlock(burnId, amount, recipient);

        bytes32 expectedBurnId = isV2
            ? keccak256(abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstance, lezOwner, recipient, amount, burnNonce, lezSlot))
            : keccak256(abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot));
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        bytes32 structHash = isV2
            ? keccak256(abi.encode(BURN_ETH_V2_TYPEHASH, burnId, sourceInstance, recipient, amount, lezOwner, burnNonce, lezSlot))
            : keccak256(abi.encode(BURN_ETH_TYPEHASH, burnId, recipient, amount, lezOwner, burnNonce, lezSlot));
        _verifyModeSignature(structHash, isQuorum, singleSig, quorumSigs);
        _settleETHUnlock(burnId, sourceInstance, recipient, amount, lezSlot, false);
    }

    function _unlockERC20Common(
        bytes32 burnId,
        bytes32 sourceInstance,
        bool isV2,
        address token,
        uint256 amount,
        address recipient,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bool isQuorum,
        bytes memory singleSig,
        bytes[] memory quorumSigs
    ) internal {
        if (isV2) {
            if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        } else if (!legacyRoutesEnabled || (!isQuorum && isCommissioned())) {
            revert LegacyRoutesDisabled();
        }
        _validateERC20Unlock(burnId, token, amount, recipient);

        bytes32 expectedBurnId = isV2
            ? keccak256(abi.encodePacked("mosoo_burn_erc20_v2", block.chainid, sourceInstance, token, lezOwner, recipient, amount, burnNonce, lezSlot))
            : keccak256(abi.encodePacked("mosoo_burn_erc20_v1", block.chainid, token, lezOwner, recipient, amount, burnNonce, lezSlot));
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        bytes32 structHash = isV2
            ? keccak256(abi.encode(BURN_ERC20_V2_TYPEHASH, burnId, sourceInstance, token, recipient, amount, lezOwner, burnNonce, lezSlot))
            : keccak256(abi.encode(BURN_ERC20_TYPEHASH, burnId, token, recipient, amount, lezOwner, burnNonce, lezSlot));
        _verifyModeSignature(structHash, isQuorum, singleSig, quorumSigs);
        _settleERC20Unlock(burnId, sourceInstance, token, recipient, amount, lezSlot, false);
    }

    function _settleETHUnlock(
        bytes32 burnId,
        bytes32 sourceInstance,
        address payable recipient,
        uint256 amount,
        uint64 lezSlot,
        bool isShielded
    ) internal {
        if (_enforceLargeWithdrawalDelay(burnId, address(0), recipient, amount, sourceInstance, LARGE_WITHDRAWAL_THRESHOLD_ETH)) {
            return;
        }
        _checkAndRecordRollingWithdrawalETH(amount);
        executedBurns[burnId] = true;
        totalUnlockedETH += amount;
        totalLockedETH -= amount;

        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();

        if (isShielded) {
            emit UnlockedShieldedETH(burnId, recipient, amount);
        } else {
            emit UnlockedETH(burnId, recipient, amount, lezSlot);
        }
    }

    function _settleERC20Unlock(
        bytes32 burnId,
        bytes32 sourceInstance,
        address token,
        address recipient,
        uint256 amount,
        uint64 lezSlot,
        bool isShielded
    ) internal {
        if (_enforceLargeWithdrawalDelay(burnId, token, recipient, amount, sourceInstance, largeWithdrawalThresholdERC20[token])) {
            return;
        }
        _checkAndRecordRollingWithdrawalERC20(token, amount);
        executedBurns[burnId] = true;
        totalLockedERC20[token] -= amount;

        _safeTransfer(token, recipient, amount);

        if (isShielded) {
            emit UnlockedShieldedERC20(burnId, token, recipient, amount);
        } else {
            emit UnlockedERC20(burnId, token, recipient, amount, lezSlot);
        }
    }

    /// @notice Propose rolling daily withdrawal volume cap for native ETH subject to 2-day timelock
    function proposeDailyWithdrawalLimitETH(uint256 newLimit) external onlyOwner {
        if (newLimit == 0) revert InvalidDailyLimit();
        pendingDailyLimitETH = newLimit;
        hasPendingDailyLimitETH = true;
        dailyLimitETHTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit DailyLimitETHChangeProposed(dailyWithdrawalLimitETH, newLimit, dailyLimitETHTimelockUnlock);
    }

    /// @notice Execute proposed daily withdrawal limit for ETH after timelock delay
    function executeDailyWithdrawalLimitETH() external onlyOwner {
        _requireFlaggedTimelock(hasPendingDailyLimitETH, dailyLimitETHTimelockUnlock);
        if (pendingDailyLimitETH == 0) revert InvalidDailyLimit();
        uint256 oldLimit = dailyWithdrawalLimitETH;
        dailyWithdrawalLimitETH = pendingDailyLimitETH;
        hasPendingDailyLimitETH = false;
        pendingDailyLimitETH = 0;
        dailyLimitETHTimelockUnlock = 0;
        emit DailyWithdrawalLimitUpdatedETH(oldLimit, dailyWithdrawalLimitETH);
    }

    /// @notice Propose rolling daily withdrawal volume cap for an ERC-20 token subject to 2-day timelock
    function proposeDailyWithdrawalLimitERC20(address token, uint256 newLimit) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (newLimit == 0) revert InvalidDailyLimit();
        pendingDailyLimitERC20[token] = newLimit;
        hasPendingDailyLimitERC20[token] = true;
        dailyLimitERC20TimelockUnlock[token] = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit DailyLimitERC20ChangeProposed(token, dailyWithdrawalLimitERC20[token], newLimit, dailyLimitERC20TimelockUnlock[token]);
    }

    /// @notice Execute proposed daily withdrawal limit for an ERC-20 token after timelock delay
    function executeDailyWithdrawalLimitERC20(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        _requireFlaggedTimelock(hasPendingDailyLimitERC20[token], dailyLimitERC20TimelockUnlock[token]);
        if (pendingDailyLimitERC20[token] == 0) revert InvalidDailyLimit();
        uint256 oldLimit = dailyWithdrawalLimitERC20[token];
        dailyWithdrawalLimitERC20[token] = pendingDailyLimitERC20[token];
        hasPendingDailyLimitERC20[token] = false;
        pendingDailyLimitERC20[token] = 0;
        dailyLimitERC20TimelockUnlock[token] = 0;
        emit DailyWithdrawalLimitUpdatedERC20(token, oldLimit, dailyWithdrawalLimitERC20[token]);
    }

    /// @notice Deprecated: direct rate-limit updates without timelock are disabled for production safety.
    function setDailyWithdrawalLimitETH(uint256) external pure {
        revert DirectGovernanceDeprecated();
    }

    /// @notice Deprecated: direct rate-limit updates without timelock are disabled for production safety.
    function setDailyWithdrawalLimitERC20(address, uint256) external pure {
        revert DirectGovernanceDeprecated();
    }

    /// @notice Pre-commissioning direct configuration for ERC-20 large-withdrawal 24h queue threshold (0 disables).
    function setLargeWithdrawalThresholdERC20(address token, uint256 threshold) external onlyOwner {
        if (productionCommissioned) revert DirectGovernanceDeprecated();
        if (token == address(0)) revert ZeroAddress();
        uint256 oldThreshold = largeWithdrawalThresholdERC20[token];
        largeWithdrawalThresholdERC20[token] = threshold;
        emit LargeWithdrawalThresholdERC20Updated(token, oldThreshold, threshold);
    }

    /// @notice Propose an ERC-20 large-withdrawal 24h queue threshold change subject to 2-day timelock.
    function proposeLargeWithdrawalThresholdERC20(address token, uint256 newThreshold) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        pendingLargeThresholdERC20[token] = newThreshold;
        hasPendingLargeThresholdERC20[token] = true;
        largeThresholdERC20TimelockUnlock[token] = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit LargeWithdrawalThresholdERC20Proposed(
            token,
            largeWithdrawalThresholdERC20[token],
            newThreshold,
            largeThresholdERC20TimelockUnlock[token]
        );
    }

    /// @notice Execute proposed ERC-20 large-withdrawal threshold after 2-day timelock delay.
    function executeLargeWithdrawalThresholdERC20(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        _requireFlaggedTimelock(hasPendingLargeThresholdERC20[token], largeThresholdERC20TimelockUnlock[token]);
        uint256 oldThreshold = largeWithdrawalThresholdERC20[token];
        largeWithdrawalThresholdERC20[token] = pendingLargeThresholdERC20[token];
        hasPendingLargeThresholdERC20[token] = false;
        pendingLargeThresholdERC20[token] = 0;
        largeThresholdERC20TimelockUnlock[token] = 0;
        emit LargeWithdrawalThresholdERC20Updated(token, oldThreshold, largeWithdrawalThresholdERC20[token]);
    }

    /// @notice Guardian/owner cancellation for pending ERC-20 large-withdrawal threshold updates.
    function cancelPendingLargeThresholdERC20(address token) external {
        _checkOwnerOrGuardian();
        if (token == address(0) || !hasPendingLargeThresholdERC20[token]) revert NoPendingGovernanceAction();
        hasPendingLargeThresholdERC20[token] = false;
        pendingLargeThresholdERC20[token] = 0;
        largeThresholdERC20TimelockUnlock[token] = 0;
        emit PendingGovernanceCancelled("largeThresholdERC20", msg.sender);
    }

    /// @notice Cancel a queued large withdrawal in an emergency (guardian or owner)
    /// @dev Permanently vetoes the burnId, preventing any re-queue or future withdrawal.
    function cancelQueuedWithdrawal(bytes32 burnId) external {
        _checkOwnerOrGuardian();
        if (queuedWithdrawalUnlockTime[burnId] == 0) revert NoQueuedWithdrawal();
        queuedWithdrawalUnlockTime[burnId] = 0;
        delete queuedWithdrawalPayloadHash[burnId];
        cancelledBurns[burnId] = true;
        emit QueuedWithdrawalCancelled(burnId, msg.sender);
    }

    /// @notice Permanently veto and invalidate any burn authorization (guardian or owner)
    function cancelBurn(bytes32 burnId) external {
        _checkOwnerOrGuardian();
        queuedWithdrawalUnlockTime[burnId] = 0;
        delete queuedWithdrawalPayloadHash[burnId];
        cancelledBurns[burnId] = true;
        emit BurnPermanentlyCancelled(burnId, msg.sender);
    }

    // --- Internal Helpers ---

    /// @dev Enforces mandatory 24h queue delay for large ETH/ERC-20 withdrawals, binding exact payload
    ///      `(chainId, verifyingContract, asset, recipient, amount, sourceInstance)` so parameters
    ///      cannot be substituted between queue creation and settlement.
    function _enforceLargeWithdrawalDelay(
        bytes32 burnId,
        address asset,
        address recipient,
        uint256 amount,
        bytes32 sourceInstance,
        uint256 threshold
    ) internal returns (bool queued) {
        if (threshold == 0 || amount < threshold) {
            return false;
        }
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), asset, recipient, amount, sourceInstance)
        );
        uint256 unlockTime = queuedWithdrawalUnlockTime[burnId];
        if (unlockTime == 0) {
            unlockTime = block.timestamp + LARGE_WITHDRAWAL_DELAY;
            queuedWithdrawalUnlockTime[burnId] = unlockTime;
            queuedWithdrawalPayloadHash[burnId] = payloadHash;
            emit WithdrawalQueued(burnId, recipient, amount, unlockTime);
            return true;
        }
        if (queuedWithdrawalPayloadHash[burnId] != payloadHash) {
            revert WithdrawalPayloadMismatch();
        }
        if (block.timestamp < unlockTime) {
            revert LargeWithdrawalPending(unlockTime);
        }
        delete queuedWithdrawalUnlockTime[burnId];
        delete queuedWithdrawalPayloadHash[burnId];
        return false;
    }

    // --- Continuous Rolling 24-Hour Helpers ---

    function _checkAndRecordRollingWithdrawalETH(uint256 amount) internal {
        uint256 limit = dailyWithdrawalLimitETH;
        if (limit == 0) revert InvalidDailyLimit();
        _checkAndRecordRollingWithdrawal(address(0), amount, limit);
    }

    function _checkAndRecordRollingWithdrawalERC20(address token, uint256 amount) internal {
        uint256 limit = dailyWithdrawalLimitERC20[token];
        if (limit == 0) revert DailyLimitNotConfigured();
        _checkAndRecordRollingWithdrawal(token, amount, limit);
    }

    function _pruneHistoryBatch(
        address asset,
        uint256 maxItems,
        uint256 cutoff
    ) internal returns (uint256 prunedCount, uint256 rolling) {
        uint256 head = _withdrawalHead[asset];
        WithdrawalRecord[] storage history = _withdrawalHistory[asset];
        uint256 len = history.length;
        rolling = _rollingWithdrawn[asset];

        while (head < len && history[head].timestamp < cutoff && prunedCount < maxItems) {
            rolling -= history[head].amount;
            delete history[head];
            head++;
            prunedCount++;
        }
        _withdrawalHead[asset] = head;
        _rollingWithdrawn[asset] = rolling;

        if (head == len) {
            assembly {
                sstore(history.slot, 0)
            }
            _withdrawalHead[asset] = 0;
        }
    }

    function _checkAndRecordRollingWithdrawal(address asset, uint256 amount, uint256 limit) internal {
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        (, uint256 rolling) = _pruneHistoryBatch(asset, MAX_CLEANUP_BATCH, cutoff);

        if (rolling + amount > limit) {
            (, rolling) = _pruneHistoryBatch(asset, MAX_PASS2_CLEANUP_BATCH, cutoff);
        }

        if (rolling + amount > limit) {
            revert DailyLimitExceeded(amount, limit - rolling);
        }

        if (amount > type(uint192).max) revert AmountExceedsUint192();
        _rollingWithdrawn[asset] = rolling + amount;
        _withdrawalHistory[asset].push(WithdrawalRecord({
            timestamp: uint64(block.timestamp),
            amount: uint192(amount)
        }));
    }

    /// @notice Permissionless pruning function to clean expired ETH withdrawal records from history
    function pruneExpiredWithdrawalsETH(uint256 maxBatch) external returns (uint256 prunedCount) {
        if (maxBatch == 0) maxBatch = MAX_CLEANUP_BATCH;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        (prunedCount, ) = _pruneHistoryBatch(address(0), maxBatch, cutoff);
    }

    /// @notice Permissionless pruning function to clean expired ERC-20 withdrawal records from history
    function pruneExpiredWithdrawalsERC20(address token, uint256 maxBatch) external returns (uint256 prunedCount) {
        if (maxBatch == 0) maxBatch = MAX_CLEANUP_BATCH;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        (prunedCount, ) = _pruneHistoryBatch(token, maxBatch, cutoff);
    }

    function _getRollingWithdrawn(address asset) internal view returns (uint256) {
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 rolling = _rollingWithdrawn[asset];
        WithdrawalRecord[] storage history = _withdrawalHistory[asset];
        for (uint256 i = _withdrawalHead[asset]; i < history.length; i++) {
            if (history[i].timestamp < cutoff) {
                rolling -= history[i].amount;
            } else {
                break;
            }
        }
        return rolling;
    }

    /// @notice Returns the current rolling 24-hour volume withdrawn for native ETH
    function getRollingWithdrawnETH() public view returns (uint256) {
        if (dailyWithdrawalLimitETH == 0) return 0;
        return _getRollingWithdrawn(address(0));
    }

    /// @notice Returns the current rolling 24-hour volume withdrawn for an ERC-20 token
    function getRollingWithdrawnERC20(address token) public view returns (uint256) {
        if (dailyWithdrawalLimitERC20[token] == 0) return 0;
        return _getRollingWithdrawn(token);
    }

    function dailyWithdrawnETH() external view returns (uint256) {
        return getRollingWithdrawnETH();
    }

    function dailyWithdrawnERC20(address token) external view returns (uint256) {
        return getRollingWithdrawnERC20(token);
    }

    function _eip712Digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function _verifyBurnSignature(
        bytes32 structHash,
        bytes memory signature
    ) internal view returns (bool) {
        if (requiredQuorum > 1) {
            return false;
        }
        address signer = _recoverSigner(_eip712Digest(structHash), signature);
        if (signer == address(0) || !isAttester[signer]) {
            return false;
        }
        if (attesterAuthority != address(0)) {
            return signer == attesterAuthority;
        }
        return true;
    }

    function _verifyQuorumSignatures(
        bytes32 structHash,
        bytes[] memory signatures
    ) internal view returns (bool) {
        if (signatures.length < requiredQuorum) {
            return false;
        }
        bytes32 eip712Digest = _eip712Digest(structHash);
        address lastSigner = address(0);
        uint256 validCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(eip712Digest, signatures[i]);
            if (signer == address(0) || !isAttester[signer]) {
                return false;
            }
            // Strictly ascending signer addresses guarantee uniqueness without duplicate allocations
            if (signer <= lastSigner) {
                return false;
            }
            lastSigner = signer;
            validCount += 1;
            if (validCount >= requiredQuorum) {
                return true;
            }
        }
        return validCount >= requiredQuorum;
    }

    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Strict EIP-2 check to prevent signature malleability
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(hash, v, r, s);
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(0x23b872dd, from, to, amount));
    }

    function _callOptionalReturn(address token, bytes memory data) internal {
        if (token.code.length == 0) revert ZeroAddress();
        (bool success, bytes memory returnData) = token.call(data);
        if (!success || (returnData.length != 0 && !abi.decode(returnData, (bool)))) {
            revert ERC20TransferFailed();
        }
    }

    function _requireTimelock(uint256 unlockTime) internal view {
        if (unlockTime == 0) revert NoPendingGovernanceAction();
        if (block.timestamp < unlockTime) revert GovernanceTimelockActive(block.timestamp, unlockTime);
    }

    function _requireFlaggedTimelock(bool hasPending, uint256 unlockTime) internal view {
        if (!hasPending) revert NoPendingGovernanceAction();
        if (block.timestamp < unlockTime) revert GovernanceTimelockActive(block.timestamp, unlockTime);
    }

    function _checkOwnerOrGuardian() internal view {
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
    }

    function _getTokenBalance(address token, address account) internal view returns (uint256) {
        bytes memory data = abi.encodeWithSelector(0x70a08231, account);
        (bool success, bytes memory returnData) = token.staticcall(data);
        if (!success || returnData.length < 32) revert BalanceQueryFailed();
        return abi.decode(returnData, (uint256));
    }

    // --- Admin & Emergency Functions ---

    function proposeAttesterAuthority(address _newAuthority) external onlyOwner {
        if (_newAuthority == address(0)) revert ZeroAddress();
        pendingAttesterAuthority = _newAuthority;
        authorityTimelockUnlock = block.timestamp + AUTHORITY_CHANGE_DELAY;
        emit AttesterAuthorityChangeProposed(attesterAuthority, _newAuthority, authorityTimelockUnlock);
    }

    /// @notice Executes a proposed attester authority rotation after timelock expiration.
    /// @dev Synchronizes attesterCount set accounting.
    /// Invariant: If rotating authority decreases the active committee below requiredQuorum,
    /// the transaction strictly reverts to prevent silent quorum degradation.
    /// Quorum modifications are restricted exclusively to proposeQuorum / executeQuorum.
    function executeAttesterAuthority() external onlyOwner {
        if (pendingAttesterAuthority == address(0)) revert NoPendingAuthority();
        if (block.timestamp < authorityTimelockUnlock) revert AuthorityTimelockActive(block.timestamp, authorityTimelockUnlock);
        address oldAuthority = attesterAuthority;
        address newAuthority = pendingAttesterAuthority;

        uint256 newAttesterCount = attesterCount;
        if (oldAuthority != newAuthority) {
            if (isAttester[oldAuthority]) {
                newAttesterCount -= 1;
            }
            if (!isAttester[newAuthority]) {
                newAttesterCount += 1;
            }
        }

        if (newAttesterCount < requiredQuorum) {
            revert InvalidQuorum();
        }

        emit AttesterAuthorityUpdated(oldAuthority, newAuthority);

        if (oldAuthority != newAuthority) {
            if (isAttester[oldAuthority]) {
                isAttester[oldAuthority] = false;
            }
            if (!isAttester[newAuthority]) {
                isAttester[newAuthority] = true;
            }
            attesterCount = newAttesterCount;
        }
        attesterAuthority = newAuthority;
        pendingAttesterAuthority = address(0);
        authorityTimelockUnlock = 0;
    }

    // --- Timelocked Multisig Governance (Finding M-04 / 4 Hardening) ---

    function proposeQuorum(uint256 _newQuorum) external onlyOwner {
        if (_newQuorum == 0 || _newQuorum > attesterCount) revert InvalidQuorum();
        if (productionCommissioned && _newQuorum < MIN_PRODUCTION_QUORUM) revert InvalidQuorum();
        pendingQuorum = _newQuorum;
        quorumTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit QuorumChangeProposed(requiredQuorum, _newQuorum, quorumTimelockUnlock);
    }

    function executeQuorum() external onlyOwner {
        _requireFlaggedTimelock(pendingQuorum != 0, quorumTimelockUnlock);
        if (pendingQuorum > attesterCount) revert InvalidQuorum();
        if (productionCommissioned && pendingQuorum < MIN_PRODUCTION_QUORUM) revert InvalidQuorum();
        uint256 oldQuorum = requiredQuorum;
        requiredQuorum = pendingQuorum;
        if (requiredQuorum >= MIN_PRODUCTION_QUORUM && attesterCount >= MIN_PRODUCTION_QUORUM) {
            productionCommissioned = true;
        }
        pendingQuorum = 0;
        quorumTimelockUnlock = 0;
        emit QuorumUpdated(oldQuorum, requiredQuorum);
    }

    function proposeAddAttester(address _attester) external onlyOwner {
        if (_attester == address(0)) revert ZeroAddress();
        if (isAttester[_attester]) revert AttesterAlreadyExists();
        pendingAddAttester = _attester;
        addAttesterTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit AttesterAddProposed(_attester, addAttesterTimelockUnlock);
    }

    function executeAddAttester() external onlyOwner {
        _requireFlaggedTimelock(pendingAddAttester != address(0), addAttesterTimelockUnlock);
        if (isAttester[pendingAddAttester]) revert AttesterAlreadyExists();
        address attester = pendingAddAttester;
        isAttester[attester] = true;
        attesterCount += 1;
        pendingAddAttester = address(0);
        addAttesterTimelockUnlock = 0;
        emit AttesterAdded(attester);
    }

    function proposeRemoveAttester(address _attester) external onlyOwner {
        if (!isAttester[_attester]) revert AttesterNotFound();
        if (attesterCount <= 1) revert InvalidQuorum();
        if (attesterCount - 1 < requiredQuorum) revert InvalidQuorum();
        pendingRemoveAttester = _attester;
        removeAttesterTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit AttesterRemoveProposed(_attester, removeAttesterTimelockUnlock);
    }

    function executeRemoveAttester() external onlyOwner {
        _requireFlaggedTimelock(pendingRemoveAttester != address(0), removeAttesterTimelockUnlock);
        if (!isAttester[pendingRemoveAttester]) revert AttesterNotFound();
        if (attesterCount <= 1) revert InvalidQuorum();
        if (attesterCount - 1 < requiredQuorum) revert InvalidQuorum();
        address attester = pendingRemoveAttester;
        isAttester[attester] = false;
        attesterCount -= 1;
        if (attester == attesterAuthority) {
            attesterAuthority = address(0);
        }
        pendingRemoveAttester = address(0);
        removeAttesterTimelockUnlock = 0;
        emit AttesterRemoved(attester);
    }

    function cancelPendingGovernance(uint8 actionType) external {
        _checkOwnerOrGuardian();
        string memory action;
        if (actionType == 1) {
            pendingQuorum = 0;
            quorumTimelockUnlock = 0;
            action = "quorum";
        } else if (actionType == 2) {
            pendingAddAttester = address(0);
            addAttesterTimelockUnlock = 0;
            action = "addAttester";
        } else if (actionType == 3) {
            pendingRemoveAttester = address(0);
            removeAttesterTimelockUnlock = 0;
            action = "removeAttester";
        } else if (actionType == 4) {
            hasPendingDailyLimitETH = false;
            pendingDailyLimitETH = 0;
            dailyLimitETHTimelockUnlock = 0;
            action = "dailyLimitETH";
        } else if (actionType == 5) {
            pendingGuardian = address(0);
            guardianTimelockUnlock = 0;
            action = "guardian";
        } else if (actionType == 6) {
            pendingAttesterAuthority = address(0);
            authorityTimelockUnlock = 0;
            action = "attesterAuthority";
        } else if (actionType == 7) {
            disableAllowlistTimelockUnlock = 0;
            action = "disableAllowlist";
        } else if (actionType == 8) {
            disableShieldedOnlyTimelockUnlock = 0;
            action = "disableShieldedOnly";
        } else if (actionType == 9) {
            disableStrictDenomTimelockUnlock = 0;
            action = "disableStrictDenom";
        } else if (actionType == 10) {
            pendingTokenAllowedAddr = address(0);
            pendingTokenAllowedFlag = false;
            tokenAllowedTimelockUnlock = 0;
            action = "tokenAllowed";
        } else if (actionType == 11) {
            pendingDenomAmount = 0;
            pendingDenomAllowed = false;
            denomTimelockUnlock = 0;
            action = "standardDenom";
        } else {
            revert NoPendingGovernanceAction();
        }
        emit PendingGovernanceCancelled(action, msg.sender);
    }

    function cancelPendingGovernanceERC20(address token) external {
        _checkOwnerOrGuardian();
        if (token == address(0) || !hasPendingDailyLimitERC20[token]) revert NoPendingGovernanceAction();
        hasPendingDailyLimitERC20[token] = false;
        pendingDailyLimitERC20[token] = 0;
        dailyLimitERC20TimelockUnlock[token] = 0;
        emit PendingGovernanceCancelled("dailyLimitERC20", msg.sender);
    }

    /// @notice Deprecated: direct attester addition without timelock is disabled for production safety.
    function addAttester(address) external pure {
        revert DirectGovernanceDeprecated();
    }

    /// @notice Deprecated: direct attester removal without timelock is disabled for production safety.
    function removeAttester(address) external pure {
        revert DirectGovernanceDeprecated();
    }

    /// @notice Deprecated: direct quorum changes without timelock are disabled for production safety.
    function setQuorum(uint256) external pure {
        revert DirectGovernanceDeprecated();
    }

    function setTokenAllowed(address token, bool allowed) external onlyOwner {
        if (productionCommissioned) revert DirectGovernanceDeprecated();
        if (token == address(0)) revert ZeroAddress();
        isTokenAllowed[token] = allowed;
        emit TokenAllowedStatusUpdated(token, allowed);
    }

    function proposeTokenAllowed(address token, bool allowed) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        pendingTokenAllowedAddr = token;
        pendingTokenAllowedFlag = allowed;
        tokenAllowedTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
    }

    function executeTokenAllowed() external onlyOwner {
        _requireTimelock(tokenAllowedTimelockUnlock);
        address token = pendingTokenAllowedAddr;
        bool allowed = pendingTokenAllowedFlag;
        pendingTokenAllowedAddr = address(0);
        pendingTokenAllowedFlag = false;
        tokenAllowedTimelockUnlock = 0;
        isTokenAllowed[token] = allowed;
        emit TokenAllowedStatusUpdated(token, allowed);
    }

    /// @notice Governance control to enable or disable legacy V1 withdrawal routes (blocked once commissioned)
    function setLegacyRoutesEnabled(bool enabled) external onlyOwner {
        if (enabled && (legacyRoutesPermanentlyDisabled || productionCommissioned)) {
            revert LegacyRoutesArePermanentlyRetired();
        }
        legacyRoutesEnabled = enabled;
        emit LegacyRoutesToggled(enabled);
    }

    /// @notice Emergency/migration shutdown to permanently cut off legacy V1 routes lacking source-instance binding
    function disableLegacyRoutes() external onlyOwner {
        legacyRoutesEnabled = false;
        emit LegacyRoutesToggled(false);
    }

    /// @notice Irreversible killswitch permanently retiring legacy V1 withdrawal routes.
    /// Once invoked, legacy routes are permanently disabled and can never be re-enabled under any circumstances.
    function permanentlyRetireLegacyRoutes() external onlyOwner {
        legacyRoutesPermanentlyDisabled = true;
        legacyRoutesEnabled = false;
        emit LegacyRoutesPermanentlyRetired();
        emit LegacyRoutesToggled(false);
    }

    function setTokenAllowlistEnabled(bool enabled) external onlyOwner {
        if (!enabled) revert DirectGovernanceDeprecated();
        tokenAllowlistEnabled = true;
        emit TokenAllowlistToggled(true);
    }

    function proposeDisableTokenAllowlist() external onlyOwner {
        disableAllowlistTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
    }

    function executeDisableTokenAllowlist() external onlyOwner {
        _requireTimelock(disableAllowlistTimelockUnlock);
        disableAllowlistTimelockUnlock = 0;
        tokenAllowlistEnabled = false;
        emit TokenAllowlistToggled(false);
    }

    function _requirePrivacyMutable(bool enabled) internal view {
        if (productionCommissioned && enabled) {
            revert PrivacySettingLocked();
        }
    }

    function setShieldedDepositsOnly(bool enabled) external onlyOwner {
        if (!enabled) {
            _requirePrivacyMutable(shieldedDepositsOnly);
            if (shieldedDepositsOnly || productionCommissioned) {
                revert DirectGovernanceDeprecated();
            }
        }
        shieldedDepositsOnly = enabled;
        emit ShieldedDepositsOnlyToggled(enabled);
    }

    function proposeDisableShieldedDepositsOnly() external onlyOwner {
        _requirePrivacyMutable(shieldedDepositsOnly);
        disableShieldedOnlyTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
    }

    function executeDisableShieldedDepositsOnly() external onlyOwner {
        _requirePrivacyMutable(shieldedDepositsOnly);
        _requireTimelock(disableShieldedOnlyTimelockUnlock);
        disableShieldedOnlyTimelockUnlock = 0;
        shieldedDepositsOnly = false;
        emit ShieldedDepositsOnlyToggled(false);
    }

    function setStrictFixedDenominationMode(bool enabled) external onlyOwner {
        if (!enabled) {
            _requirePrivacyMutable(strictFixedDenominationMode);
            if (strictFixedDenominationMode || productionCommissioned) {
                revert DirectGovernanceDeprecated();
            }
        }
        strictFixedDenominationMode = enabled;
        emit StrictDenominationModeToggled(enabled);
    }

    function proposeDisableStrictDenominationMode() external onlyOwner {
        _requirePrivacyMutable(strictFixedDenominationMode);
        disableStrictDenomTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
    }

    function executeDisableStrictDenominationMode() external onlyOwner {
        _requirePrivacyMutable(strictFixedDenominationMode);
        _requireTimelock(disableStrictDenomTimelockUnlock);
        disableStrictDenomTimelockUnlock = 0;
        strictFixedDenominationMode = false;
        emit StrictDenominationModeToggled(false);
    }

    function setStandardDenomination(uint256 denomination, bool allowed) external onlyOwner {
        if (productionCommissioned) revert DirectGovernanceDeprecated();
        if (denomination == 0) revert ZeroAmount();
        isStandardDenomination[denomination] = allowed;
        emit StandardDenominationUpdated(denomination, allowed);
    }

    function proposeStandardDenomination(uint256 denomination, bool allowed) external onlyOwner {
        if (denomination == 0) revert ZeroAmount();
        pendingDenomAmount = denomination;
        pendingDenomAllowed = allowed;
        denomTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
    }

    function executeStandardDenomination() external onlyOwner {
        _requireTimelock(denomTimelockUnlock);
        uint256 denomination = pendingDenomAmount;
        bool allowed = pendingDenomAllowed;
        pendingDenomAmount = 0;
        pendingDenomAllowed = false;
        denomTimelockUnlock = 0;
        isStandardDenomination[denomination] = allowed;
        emit StandardDenominationUpdated(denomination, allowed);
    }

    function proposeGuardian(address _newGuardian) external onlyOwner {
        if (_newGuardian == address(0)) revert ZeroAddress();
        if (_newGuardian == owner || _newGuardian == pendingOwner) revert GuardianMustNotBeOwner();
        pendingGuardian = _newGuardian;
        guardianTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit GuardianChangeProposed(guardian, _newGuardian, guardianTimelockUnlock);
    }

    function executeGuardian() external onlyOwner {
        _requireFlaggedTimelock(pendingGuardian != address(0), guardianTimelockUnlock);
        if (pendingGuardian == owner) revert GuardianMustNotBeOwner();
        address oldGuardian = guardian;
        guardian = pendingGuardian;
        pendingGuardian = address(0);
        guardianTimelockUnlock = 0;
        emit GuardianUpdated(oldGuardian, guardian);
    }

    /// @notice Deprecated: direct guardian updates without timelock are disabled for production safety.
    function setGuardian(address) external pure {
        revert DirectGovernanceDeprecated();
    }

    function emergencyPause() external {
        _checkOwnerOrGuardian();
        paused = true;
        emit PausedStateChanged(true);
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedStateChanged(_paused);
    }

    // Two-step ownership transfer preventing accidental ownership loss
    function transferOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert ZeroAddress();
        if (_newOwner == guardian || _newOwner == pendingGuardian) revert GuardianMustNotBeOwner();
        pendingOwner = _newOwner;
        emit OwnershipTransferStarted(owner, _newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        if (pendingOwner == guardian || pendingOwner == pendingGuardian) revert GuardianMustNotBeOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // --- Receive Fallback ---
    receive() external payable {
        // Direct transfers not permitted to prevent unindexed deposits
        revert Unauthorized();
    }
}
