// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title MosooLocker
 * @notice Canonical Ethereum Escrow and Settlement contract for the Mosoo Light Client Bridge
 *         connecting Ethereum (Mainnet / Sepolia / Holesky) and the Logos Execution Zone (LEZ).
 *
 * @dev Comprehensive Trust Model & Security Hardening:
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
    uint256 public constant AUTHORITY_CHANGE_DELAY = 1 days;

    /// @notice Multi-signer attester committee membership and M-of-N threshold quorum
    mapping(address => bool) public isAttester;
    uint256 public attesterCount;
    uint256 public requiredQuorum;

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

    // --- Rate Limiting & Timelock Defense-in-Depth ---

    /// @dev Continuous rolling 24-hour window record
    struct WithdrawalRecord {
        uint64 timestamp;
        uint192 amount;
    }

    uint256 public constant ROLLING_WINDOW = 1 days;

    /// @notice Rolling daily withdrawal limit for ETH (0 = disabled/unlimited)
    uint256 public dailyWithdrawalLimitETH;
    WithdrawalRecord[] private _ethWithdrawals;
    uint256 private _ethWithdrawalHead;
    uint256 private _rollingWithdrawnETH;

    /// @notice Rolling daily withdrawal limits for ERC-20 tokens (token => limit)
    mapping(address => uint256) public dailyWithdrawalLimitERC20;
    mapping(address => WithdrawalRecord[]) private _erc20Withdrawals;
    mapping(address => uint256) private _erc20WithdrawalHead;
    mapping(address => uint256) private _rollingWithdrawnERC20;

    /// @notice Multi-signer governance timelock (2-day delay for attester/quorum modifications)
    uint256 public constant GOVERNANCE_TIMELOCK_DELAY = 2 days;
    /// @notice Maximum number of expired withdrawal records cleaned up per transaction to guarantee O(1) gas
    uint256 public constant MAX_CLEANUP_BATCH = 32;
    /// @notice Maximum number of records pruned in second-pass cleanup to bound gas on limit contention
    uint256 public constant MAX_PASS2_CLEANUP_BATCH = 128;

    uint256 public pendingQuorum;
    uint256 public quorumTimelockUnlock;
    address public pendingAddAttester;
    uint256 public addAttesterTimelockUnlock;
    address public pendingRemoveAttester;
    uint256 public removeAttesterTimelockUnlock;
    address public pendingGuardian;
    uint256 public guardianTimelockUnlock;

    /// @notice Timelocked rate-limit administration (2-day timelock delay)
    uint256 public pendingDailyLimitETH;
    uint256 public dailyLimitETHTimelockUnlock;
    bool public hasPendingDailyLimitETH;

    mapping(address => uint256) public pendingDailyLimitERC20;
    mapping(address => uint256) public dailyLimitERC20TimelockUnlock;
    mapping(address => bool) public hasPendingDailyLimitERC20;

    /// @notice Large withdrawal threshold requiring mandatory timelock delay
    uint256 public constant LARGE_WITHDRAWAL_THRESHOLD_ETH = 10 ether;
    uint256 public constant LARGE_WITHDRAWAL_DELAY = 1 days;

    /// @notice Queued large withdrawals: burnId => executableTimestamp
    mapping(bytes32 => uint256) public queuedWithdrawalUnlockTime;

    /// @notice Permanently cancelled burns (cannot be re-queued or unlocked by anyone)
    mapping(bytes32 => bool) public cancelledBurns;

    // --- EIP-712 Domain Separation ---
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public constant BURN_ETH_TYPEHASH = keccak256(
        "BurnETH(bytes32 burnId,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    bytes32 public constant BURN_ERC20_TYPEHASH = keccak256(
        "BurnERC20(bytes32 burnId,address token,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    // --- V2 Cross-Instance Domain-Separated Typehashes ---
    bytes32 public constant BURN_ETH_V2_TYPEHASH = keccak256(
        "BurnETHV2(bytes32 burnId,bytes32 sourceInstance,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
    );

    bytes32 public constant BURN_ERC20_V2_TYPEHASH = keccak256(
        "BurnERC20V2(bytes32 burnId,bytes32 sourceInstance,address token,address recipient,uint256 amount,bytes32 lezOwner,uint64 burnNonce,uint64 lezSlot)"
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
    event QuorumChangeProposed(uint256 currentQuorum, uint256 proposedQuorum, uint256 unlockTimestamp);
    event AttesterAddProposed(address indexed proposedAttester, uint256 unlockTimestamp);
    event AttesterRemoveProposed(address indexed proposedAttester, uint256 unlockTimestamp);
    event DailyLimitETHChangeProposed(uint256 currentLimit, uint256 proposedLimit, uint256 unlockTimestamp);
    event DailyLimitERC20ChangeProposed(address indexed token, uint256 currentLimit, uint256 proposedLimit, uint256 unlockTimestamp);
    event PendingGovernanceCancelled(string action, address indexed cancelledBy);

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
    error AttesterNotFound();
    error GovernanceTimelockActive(uint256 currentTime, uint256 unlockTime);
    error NoPendingGovernanceAction();
    error DirectGovernanceDeprecated();

    // --- Modifiers ---

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier nonReentrant() {
        if (_status == _ENTERED) revert ReentrancyGuardReentrantCall();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // --- Constructor ---

    constructor(address _attesterAuthority, address _guardian) {
        if (_attesterAuthority == address(0)) revert ZeroAddress();
        owner = msg.sender;
        guardian = _guardian != address(0) ? _guardian : msg.sender; // Finding M-05/Chat 17 hardening: support independent guardian
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
        if (msg.value == 0) revert ZeroAmount();
        if (lezRecipient == bytes32(0)) revert ZeroAddress();

        depositNonce += 1;
        nonce = depositNonce;
        totalLockedETH += msg.value;

        emit DepositETH(msg.sender, lezRecipient, msg.value, nonce);
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
        if (amount == 0) revert ZeroAmount();
        if (token == address(0) || lezRecipient == bytes32(0)) revert ZeroAddress();
        if (token.code.length == 0) revert ZeroAddress();
        if (tokenAllowlistEnabled && !isTokenAllowed[token]) revert TokenNotAllowed();

        uint256 balanceBefore = _getTokenBalance(token, address(this));
        _safeTransferFrom(token, msg.sender, address(this), amount);
        uint256 actualAmount = _getTokenBalance(token, address(this)) - balanceBefore;
        if (actualAmount == 0) revert ZeroAmount();

        depositNonce += 1;
        nonce = depositNonce;
        totalLockedERC20[token] += actualAmount;

        emit DepositERC20(token, msg.sender, lezRecipient, actualAmount, nonce);
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
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedETH < amount || address(this).balance < amount) revert InsufficientLockedETH();

        // 1. Verify burnId canonical derivation: keccak256("mosoo_burn_v1" || chain_id || lezOwner || recipient || amount || nonce || slot)
        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_v1",
                block.chainid,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        // 2. Verify signature using EIP-712 structured data (strictly binding verifyingContract address(this))
        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ETH_TYPEHASH,
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyBurnSignature(structHash, attestationSignature)) {
            revert InvalidBurnProof();
        }

        // 3. Defense-in-Depth: Timelock delay for large withdrawals (>= 10 ETH)
        if (amount >= LARGE_WITHDRAWAL_THRESHOLD_ETH) {
            uint256 unlockTime = queuedWithdrawalUnlockTime[burnId];
            if (unlockTime == 0) {
                unlockTime = block.timestamp + LARGE_WITHDRAWAL_DELAY;
                queuedWithdrawalUnlockTime[burnId] = unlockTime;
                emit WithdrawalQueued(burnId, recipient, amount, unlockTime);
                return;
            }
            if (block.timestamp < unlockTime) {
                revert LargeWithdrawalPending(unlockTime);
            }
        }

        // 4. Defense-in-Depth: True rolling 24-hour continuous sliding volume limit check
        _checkAndRecordRollingWithdrawalETH(amount);

        // 5. Mark burn nullifier as spent (prevents replay)
        executedBurns[burnId] = true;
        totalUnlockedETH += amount;
        totalLockedETH -= amount;

        // 6. Transfer ETH to recipient
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();

        emit UnlockedETH(burnId, recipient, amount, lezSlot);
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
        if (amount == 0) revert ZeroAmount();
        if (token == address(0) || recipient == address(0)) revert ZeroAddress();
        if (token.code.length == 0) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedERC20[token] < amount) revert InsufficientLockedERC20();

        // 1. Verify burnId canonical derivation for ERC-20
        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_erc20_v1",
                block.chainid,
                token,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        // 2. Verify signature using EIP-712 structured data (strictly binding verifyingContract address(this))
        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ERC20_TYPEHASH,
                burnId,
                token,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyBurnSignature(structHash, attestationSignature)) {
            revert InvalidBurnProof();
        }

        // 3. Defense-in-Depth: True rolling 24-hour continuous sliding volume limit check
        _checkAndRecordRollingWithdrawalERC20(token, amount);

        // 4. Mark burn nullifier and update accounting
        executedBurns[burnId] = true;
        totalLockedERC20[token] -= amount;

        // 5. Transfer tokens to recipient
        _safeTransfer(token, recipient, amount);

        emit UnlockedERC20(burnId, token, recipient, amount, lezSlot);
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
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();
        if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedETH < amount || address(this).balance < amount) revert InsufficientLockedETH();

        // 1. Verify burnId canonical derivation strictly binding sourceInstance (Finding P2 / Cross-Instance Domain Separation)
        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_v2",
                block.chainid,
                sourceInstance,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        // 2. Verify signature using EIP-712 structured data strictly binding sourceInstance
        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ETH_V2_TYPEHASH,
                burnId,
                sourceInstance,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyBurnSignature(structHash, attestationSignature)) {
            revert InvalidBurnProof();
        }

        // 3. Timelock delay for large withdrawals
        if (amount >= LARGE_WITHDRAWAL_THRESHOLD_ETH) {
            uint256 unlockTime = queuedWithdrawalUnlockTime[burnId];
            if (unlockTime == 0) {
                unlockTime = block.timestamp + LARGE_WITHDRAWAL_DELAY;
                queuedWithdrawalUnlockTime[burnId] = unlockTime;
                emit WithdrawalQueued(burnId, recipient, amount, unlockTime);
                return;
            }
            if (block.timestamp < unlockTime) {
                revert LargeWithdrawalPending(unlockTime);
            }
        }

        // 4. Rolling limit check
        _checkAndRecordRollingWithdrawalETH(amount);

        // 5. Mark burn nullifier as spent
        executedBurns[burnId] = true;
        totalUnlockedETH += amount;
        totalLockedETH -= amount;

        // 6. Transfer ETH to recipient
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();

        emit UnlockedETH(burnId, recipient, amount, lezSlot);
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
        if (amount == 0) revert ZeroAmount();
        if (token == address(0) || recipient == address(0)) revert ZeroAddress();
        if (sourceInstance == bytes32(0)) revert InvalidSourceInstance();
        if (token.code.length == 0) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedERC20[token] < amount) revert InsufficientLockedERC20();

        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_erc20_v2",
                block.chainid,
                sourceInstance,
                token,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ERC20_V2_TYPEHASH,
                burnId,
                sourceInstance,
                token,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyBurnSignature(structHash, attestationSignature)) {
            revert InvalidBurnProof();
        }

        _checkAndRecordRollingWithdrawalERC20(token, amount);

        executedBurns[burnId] = true;
        totalLockedERC20[token] -= amount;

        _safeTransfer(token, recipient, amount);

        emit UnlockedERC20(burnId, token, recipient, amount, lezSlot);
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
    function unlockETHWithQuorum(
        bytes32 burnId,
        address payable recipient,
        uint256 amount,
        bytes32 lezOwner,
        uint64 burnNonce,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedETH < amount || address(this).balance < amount) revert InsufficientLockedETH();

        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_v1",
                block.chainid,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ETH_TYPEHASH,
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyQuorumSignatures(structHash, signatures)) {
            revert InvalidBurnProof();
        }

        if (amount >= LARGE_WITHDRAWAL_THRESHOLD_ETH) {
            uint256 unlockTime = queuedWithdrawalUnlockTime[burnId];
            if (unlockTime == 0) {
                unlockTime = block.timestamp + LARGE_WITHDRAWAL_DELAY;
                queuedWithdrawalUnlockTime[burnId] = unlockTime;
                emit WithdrawalQueued(burnId, recipient, amount, unlockTime);
                return;
            }
            if (block.timestamp < unlockTime) {
                revert LargeWithdrawalPending(unlockTime);
            }
        }

        // Defense-in-Depth: True rolling 24-hour continuous sliding volume limit check
        _checkAndRecordRollingWithdrawalETH(amount);

        executedBurns[burnId] = true;
        totalUnlockedETH += amount;
        totalLockedETH -= amount;

        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();

        emit UnlockedETH(burnId, recipient, amount, lezSlot);
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
        if (amount == 0) revert ZeroAmount();
        if (token == address(0) || recipient == address(0)) revert ZeroAddress();
        if (token.code.length == 0) revert ZeroAddress();
        if (executedBurns[burnId]) revert BurnAlreadyExecuted();
        if (cancelledBurns[burnId]) revert BurnCancelled();
        if (totalLockedERC20[token] < amount) revert InsufficientLockedERC20();

        bytes32 expectedBurnId = keccak256(
            abi.encodePacked(
                "mosoo_burn_erc20_v1",
                block.chainid,
                token,
                lezOwner,
                recipient,
                amount,
                burnNonce,
                lezSlot
            )
        );
        if (burnId != expectedBurnId) revert InvalidBurnProof();

        bytes32 structHash = keccak256(
            abi.encode(
                BURN_ERC20_TYPEHASH,
                burnId,
                token,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        if (!_verifyQuorumSignatures(structHash, signatures)) {
            revert InvalidBurnProof();
        }

        // Defense-in-Depth: True rolling 24-hour continuous sliding volume limit check
        _checkAndRecordRollingWithdrawalERC20(token, amount);

        executedBurns[burnId] = true;
        totalLockedERC20[token] -= amount;

        _safeTransfer(token, recipient, amount);

        emit UnlockedERC20(burnId, token, recipient, amount, lezSlot);
    }

    /// @notice Propose rolling daily withdrawal volume cap for native ETH subject to 2-day timelock
    function proposeDailyWithdrawalLimitETH(uint256 newLimit) external onlyOwner {
        pendingDailyLimitETH = newLimit;
        hasPendingDailyLimitETH = true;
        dailyLimitETHTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit DailyLimitETHChangeProposed(dailyWithdrawalLimitETH, newLimit, dailyLimitETHTimelockUnlock);
    }

    /// @notice Execute proposed daily withdrawal limit for ETH after timelock delay
    function executeDailyWithdrawalLimitETH() external onlyOwner {
        if (!hasPendingDailyLimitETH) revert NoPendingGovernanceAction();
        if (block.timestamp < dailyLimitETHTimelockUnlock) {
            revert GovernanceTimelockActive(block.timestamp, dailyLimitETHTimelockUnlock);
        }
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
        pendingDailyLimitERC20[token] = newLimit;
        hasPendingDailyLimitERC20[token] = true;
        dailyLimitERC20TimelockUnlock[token] = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit DailyLimitERC20ChangeProposed(token, dailyWithdrawalLimitERC20[token], newLimit, dailyLimitERC20TimelockUnlock[token]);
    }

    /// @notice Execute proposed daily withdrawal limit for an ERC-20 token after timelock delay
    function executeDailyWithdrawalLimitERC20(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (!hasPendingDailyLimitERC20[token]) revert NoPendingGovernanceAction();
        if (block.timestamp < dailyLimitERC20TimelockUnlock[token]) {
            revert GovernanceTimelockActive(block.timestamp, dailyLimitERC20TimelockUnlock[token]);
        }
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

    /// @notice Cancel a queued large withdrawal in an emergency (guardian or owner)
    /// @dev Permanently vetoes the burnId, preventing any re-queue or future withdrawal.
    function cancelQueuedWithdrawal(bytes32 burnId) external {
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
        if (queuedWithdrawalUnlockTime[burnId] == 0) revert NoQueuedWithdrawal();
        queuedWithdrawalUnlockTime[burnId] = 0;
        cancelledBurns[burnId] = true;
        emit QueuedWithdrawalCancelled(burnId, msg.sender);
    }

    /// @notice Permanently veto and invalidate any burn authorization (guardian or owner)
    function cancelBurn(bytes32 burnId) external {
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
        queuedWithdrawalUnlockTime[burnId] = 0;
        cancelledBurns[burnId] = true;
        emit BurnPermanentlyCancelled(burnId, msg.sender);
    }

    // --- Internal Helpers ---

    // --- Continuous Rolling 24-Hour Helpers ---

    function _checkAndRecordRollingWithdrawalETH(uint256 amount) internal {
        if (dailyWithdrawalLimitETH == 0) return;

        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 head = _ethWithdrawalHead;
        uint256 len = _ethWithdrawals.length;
        uint256 rolling = _rollingWithdrawnETH;
        uint256 cleaned = 0;

        // Pass 1: Bounded cleanup for normal gas efficiency
        while (head < len && _ethWithdrawals[head].timestamp < cutoff && cleaned < MAX_CLEANUP_BATCH) {
            rolling -= _ethWithdrawals[head].amount;
            delete _ethWithdrawals[head];
            head++;
            cleaned++;
        }

        // Pass 2: If the proposed withdrawal would exceed limit, continue pruning expired records
        // up to MAX_PASS2_CLEANUP_BATCH so valid withdrawals are not blocked by uncleaned records,
        // while strictly bounding maximum per-call gas expenditure (predictable gas defense)
        if (rolling + amount > dailyWithdrawalLimitETH) {
            uint256 pass2Cleaned = 0;
            while (head < len && _ethWithdrawals[head].timestamp < cutoff && pass2Cleaned < MAX_PASS2_CLEANUP_BATCH) {
                rolling -= _ethWithdrawals[head].amount;
                delete _ethWithdrawals[head];
                head++;
                pass2Cleaned++;
            }
        }

        _ethWithdrawalHead = head;

        if (rolling + amount > dailyWithdrawalLimitETH) {
            revert DailyLimitExceeded(amount, dailyWithdrawalLimitETH - rolling);
        }

        if (head == len) {
            assembly {
                sstore(_ethWithdrawals.slot, 0)
            }
            _ethWithdrawalHead = 0;
        }

        _rollingWithdrawnETH = rolling + amount;
        _ethWithdrawals.push(WithdrawalRecord({
            timestamp: uint64(block.timestamp),
            amount: uint192(amount)
        }));
    }

    function _checkAndRecordRollingWithdrawalERC20(address token, uint256 amount) internal {
        uint256 limit = dailyWithdrawalLimitERC20[token];
        if (limit == 0) return;

        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 head = _erc20WithdrawalHead[token];
        WithdrawalRecord[] storage history = _erc20Withdrawals[token];
        uint256 len = history.length;
        uint256 rolling = _rollingWithdrawnERC20[token];
        uint256 cleaned = 0;

        // Pass 1: Bounded cleanup for normal gas efficiency
        while (head < len && history[head].timestamp < cutoff && cleaned < MAX_CLEANUP_BATCH) {
            rolling -= history[head].amount;
            delete history[head];
            head++;
            cleaned++;
        }

        // Pass 2: If the proposed withdrawal would exceed limit, continue pruning expired records
        // up to MAX_PASS2_CLEANUP_BATCH so valid withdrawals are not blocked by uncleaned records,
        // while strictly bounding maximum per-call gas expenditure (predictable gas defense)
        if (rolling + amount > limit) {
            uint256 pass2Cleaned = 0;
            while (head < len && history[head].timestamp < cutoff && pass2Cleaned < MAX_PASS2_CLEANUP_BATCH) {
                rolling -= history[head].amount;
                delete history[head];
                head++;
                pass2Cleaned++;
            }
        }

        _erc20WithdrawalHead[token] = head;

        if (rolling + amount > limit) {
            revert DailyLimitExceeded(amount, limit - rolling);
        }

        if (head == len) {
            assembly {
                sstore(history.slot, 0)
            }
            _erc20WithdrawalHead[token] = 0;
        }

        _rollingWithdrawnERC20[token] = rolling + amount;
        history.push(WithdrawalRecord({
            timestamp: uint64(block.timestamp),
            amount: uint192(amount)
        }));
    }

    /// @notice Permissionless pruning function to clean expired ETH withdrawal records from history
    /// @param maxBatch Maximum number of records to prune in this transaction (0 = default MAX_CLEANUP_BATCH)
    /// @return prunedCount Number of expired records successfully deleted
    function pruneExpiredWithdrawalsETH(uint256 maxBatch) external returns (uint256 prunedCount) {
        if (maxBatch == 0) maxBatch = MAX_CLEANUP_BATCH;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 head = _ethWithdrawalHead;
        uint256 len = _ethWithdrawals.length;
        uint256 rolling = _rollingWithdrawnETH;

        while (head < len && _ethWithdrawals[head].timestamp < cutoff && prunedCount < maxBatch) {
            rolling -= _ethWithdrawals[head].amount;
            delete _ethWithdrawals[head];
            head++;
            prunedCount++;
        }
        _ethWithdrawalHead = head;
        _rollingWithdrawnETH = rolling;

        if (head == len) {
            assembly {
                sstore(_ethWithdrawals.slot, 0)
            }
            _ethWithdrawalHead = 0;
        }
    }

    /// @notice Permissionless pruning function to clean expired ERC-20 withdrawal records from history
    /// @param token The ERC-20 token address to prune
    /// @param maxBatch Maximum number of records to prune in this transaction (0 = default MAX_CLEANUP_BATCH)
    /// @return prunedCount Number of expired records successfully deleted
    function pruneExpiredWithdrawalsERC20(address token, uint256 maxBatch) external returns (uint256 prunedCount) {
        if (maxBatch == 0) maxBatch = MAX_CLEANUP_BATCH;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 head = _erc20WithdrawalHead[token];
        WithdrawalRecord[] storage history = _erc20Withdrawals[token];
        uint256 len = history.length;
        uint256 rolling = _rollingWithdrawnERC20[token];

        while (head < len && history[head].timestamp < cutoff && prunedCount < maxBatch) {
            rolling -= history[head].amount;
            delete history[head];
            head++;
            prunedCount++;
        }
        _erc20WithdrawalHead[token] = head;
        _rollingWithdrawnERC20[token] = rolling;

        if (head == len) {
            assembly {
                sstore(history.slot, 0)
            }
            _erc20WithdrawalHead[token] = 0;
        }
    }

    /// @notice Returns the current rolling 24-hour volume withdrawn for native ETH
    function getRollingWithdrawnETH() public view returns (uint256) {
        if (dailyWithdrawalLimitETH == 0) return 0;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 rolling = _rollingWithdrawnETH;
        for (uint256 i = _ethWithdrawalHead; i < _ethWithdrawals.length; i++) {
            if (_ethWithdrawals[i].timestamp < cutoff) {
                rolling -= _ethWithdrawals[i].amount;
            } else {
                break;
            }
        }
        return rolling;
    }

    /// @notice Returns the current rolling 24-hour volume withdrawn for an ERC-20 token
    function getRollingWithdrawnERC20(address token) public view returns (uint256) {
        if (dailyWithdrawalLimitERC20[token] == 0) return 0;
        uint256 cutoff = block.timestamp > ROLLING_WINDOW ? block.timestamp - ROLLING_WINDOW : 0;
        uint256 rolling = _rollingWithdrawnERC20[token];
        WithdrawalRecord[] storage history = _erc20Withdrawals[token];
        for (uint256 i = _erc20WithdrawalHead[token]; i < history.length; i++) {
            if (history[i].timestamp < cutoff) {
                rolling -= history[i].amount;
            } else {
                break;
            }
        }
        return rolling;
    }

    function dailyWithdrawnETH() external view returns (uint256) {
        return getRollingWithdrawnETH();
    }

    function dailyWithdrawnERC20(address token) external view returns (uint256) {
        return getRollingWithdrawnERC20(token);
    }

    function _verifyBurnSignature(
        bytes32 structHash,
        bytes calldata signature
    ) internal view returns (bool) {
        if (requiredQuorum > 1) {
            // When M-of-N quorum > 1, callers must invoke unlockETHWithQuorum / unlockERC20WithQuorum
            return false;
        }
        bytes32 eip712Digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );
        address signer = _recoverSigner(eip712Digest, signature);
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
        bytes[] calldata signatures
    ) internal view returns (bool) {
        if (signatures.length < requiredQuorum) {
            return false;
        }
        bytes32 eip712Digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );
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
        if (token.code.length == 0) revert ZeroAddress();
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, to, amount);
        (bool success, bytes memory returnData) = token.call(data);
        if (!success || (returnData.length != 0 && !abi.decode(returnData, (bool)))) {
            revert ERC20TransferFailed();
        }
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        if (token.code.length == 0) revert ZeroAddress();
        bytes memory data = abi.encodeWithSelector(0x23b87266, from, to, amount);
        (bool success, bytes memory returnData) = token.call(data);
        if (!success || (returnData.length != 0 && !abi.decode(returnData, (bool)))) {
            revert ERC20TransferFailed();
        }
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
        pendingQuorum = _newQuorum;
        quorumTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit QuorumChangeProposed(requiredQuorum, _newQuorum, quorumTimelockUnlock);
    }

    function executeQuorum() external onlyOwner {
        if (pendingQuorum == 0) revert NoPendingGovernanceAction();
        if (block.timestamp < quorumTimelockUnlock) {
            revert GovernanceTimelockActive(block.timestamp, quorumTimelockUnlock);
        }
        if (pendingQuorum > attesterCount) revert InvalidQuorum();
        uint256 oldQuorum = requiredQuorum;
        requiredQuorum = pendingQuorum;
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
        if (pendingAddAttester == address(0)) revert NoPendingGovernanceAction();
        if (block.timestamp < addAttesterTimelockUnlock) {
            revert GovernanceTimelockActive(block.timestamp, addAttesterTimelockUnlock);
        }
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
        if (pendingRemoveAttester == address(0)) revert NoPendingGovernanceAction();
        if (block.timestamp < removeAttesterTimelockUnlock) {
            revert GovernanceTimelockActive(block.timestamp, removeAttesterTimelockUnlock);
        }
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
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
        if (actionType == 1) {
            pendingQuorum = 0;
            quorumTimelockUnlock = 0;
            emit PendingGovernanceCancelled("quorum", msg.sender);
        } else if (actionType == 2) {
            pendingAddAttester = address(0);
            addAttesterTimelockUnlock = 0;
            emit PendingGovernanceCancelled("addAttester", msg.sender);
        } else if (actionType == 3) {
            pendingRemoveAttester = address(0);
            removeAttesterTimelockUnlock = 0;
            emit PendingGovernanceCancelled("removeAttester", msg.sender);
        } else if (actionType == 4) {
            hasPendingDailyLimitETH = false;
            pendingDailyLimitETH = 0;
            dailyLimitETHTimelockUnlock = 0;
            emit PendingGovernanceCancelled("dailyLimitETH", msg.sender);
        } else if (actionType == 5) {
            pendingGuardian = address(0);
            guardianTimelockUnlock = 0;
            emit PendingGovernanceCancelled("guardian", msg.sender);
        } else if (actionType == 6) {
            pendingAttesterAuthority = address(0);
            authorityTimelockUnlock = 0;
            emit PendingGovernanceCancelled("attesterAuthority", msg.sender);
        } else {
            revert NoPendingGovernanceAction();
        }
    }

    function cancelPendingGovernanceERC20(address token) external {
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
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
        if (token == address(0)) revert ZeroAddress();
        isTokenAllowed[token] = allowed;
        emit TokenAllowedStatusUpdated(token, allowed);
    }

    function setTokenAllowlistEnabled(bool enabled) external onlyOwner {
        tokenAllowlistEnabled = enabled;
        emit TokenAllowlistToggled(enabled);
    }

    function proposeGuardian(address _newGuardian) external onlyOwner {
        if (_newGuardian == address(0)) revert ZeroAddress();
        pendingGuardian = _newGuardian;
        guardianTimelockUnlock = block.timestamp + GOVERNANCE_TIMELOCK_DELAY;
        emit GuardianChangeProposed(guardian, _newGuardian, guardianTimelockUnlock);
    }

    function executeGuardian() external onlyOwner {
        if (pendingGuardian == address(0)) revert NoPendingGovernanceAction();
        if (block.timestamp < guardianTimelockUnlock) {
            revert GovernanceTimelockActive(block.timestamp, guardianTimelockUnlock);
        }
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
        if (msg.sender != owner && msg.sender != guardian) revert Unauthorized();
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
        pendingOwner = _newOwner;
        emit OwnershipTransferStarted(owner, _newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
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
