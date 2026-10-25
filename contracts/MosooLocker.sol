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

    /// @notice Rolling daily withdrawal limit for ETH (0 = disabled/unlimited)
    uint256 public dailyWithdrawalLimitETH;
    uint256 public currentDayWindowETH;
    uint256 public dailyWithdrawnETH;

    /// @notice Rolling daily withdrawal limits for ERC-20 tokens (token => limit)
    mapping(address => uint256) public dailyWithdrawalLimitERC20;
    mapping(address => uint256) public currentDayWindowERC20;
    mapping(address => uint256) public dailyWithdrawnERC20;

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
    event GuardianUpdated(address indexed previousGuardian, address indexed newGuardian);
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

    // --- Errors ---

    error ZeroAmount();
    error ZeroAddress();
    error ContractPaused();
    error Unauthorized();
    error ReentrancyGuardReentrantCall();
    error BurnAlreadyExecuted();
    error BurnCancelled();
    error InvalidBurnProof();
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

    constructor(address _attesterAuthority) {
        if (_attesterAuthority == address(0)) revert ZeroAddress();
        owner = msg.sender;
        attesterAuthority = _attesterAuthority;
        tokenAllowlistEnabled = true; // Enabled by default for strict production safety
        _status = _NOT_ENTERED;
        emit OwnershipTransferred(address(0), msg.sender);
        emit AttesterAuthorityUpdated(address(0), _attesterAuthority);
        emit TokenAllowlistToggled(true);
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

        // 1. Verify burnId canonical derivation: sha256("mosoo_burn_v1" || chain_id || lezOwner || recipient || amount || nonce || slot)
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

        // 4. Defense-in-Depth: Rolling 24-hour daily volume limit check
        if (dailyWithdrawalLimitETH > 0) {
            uint256 currentDay = block.timestamp / 1 days;
            if (currentDay > currentDayWindowETH) {
                currentDayWindowETH = currentDay;
                dailyWithdrawnETH = 0;
            }
            if (dailyWithdrawnETH + amount > dailyWithdrawalLimitETH) {
                revert DailyLimitExceeded(amount, dailyWithdrawalLimitETH - dailyWithdrawnETH);
            }
            dailyWithdrawnETH += amount;
        }

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

        // 3. Defense-in-Depth: Rolling daily volume limit for token
        uint256 limit = dailyWithdrawalLimitERC20[token];
        if (limit > 0) {
            uint256 currentDay = block.timestamp / 1 days;
            if (currentDay > currentDayWindowERC20[token]) {
                currentDayWindowERC20[token] = currentDay;
                dailyWithdrawnERC20[token] = 0;
            }
            if (dailyWithdrawnERC20[token] + amount > limit) {
                revert DailyLimitExceeded(amount, limit - dailyWithdrawnERC20[token]);
            }
            dailyWithdrawnERC20[token] += amount;
        }

        // 4. Mark burn nullifier and update accounting
        executedBurns[burnId] = true;
        totalLockedERC20[token] -= amount;

        // 5. Transfer tokens to recipient
        _safeTransfer(token, recipient, amount);

        emit UnlockedERC20(burnId, token, recipient, amount, lezSlot);
    }

    /// @notice Configure rolling daily withdrawal volume cap for native ETH
    function setDailyWithdrawalLimitETH(uint256 newLimit) external onlyOwner {
        uint256 oldLimit = dailyWithdrawalLimitETH;
        dailyWithdrawalLimitETH = newLimit;
        emit DailyWithdrawalLimitUpdatedETH(oldLimit, newLimit);
    }

    /// @notice Configure rolling daily withdrawal volume cap for a specific ERC-20 token
    function setDailyWithdrawalLimitERC20(address token, uint256 newLimit) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        uint256 oldLimit = dailyWithdrawalLimitERC20[token];
        dailyWithdrawalLimitERC20[token] = newLimit;
        emit DailyWithdrawalLimitUpdatedERC20(token, oldLimit, newLimit);
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

    function _verifyBurnSignature(
        bytes32 structHash,
        bytes calldata signature
    ) internal view returns (bool) {
        // EIP-712 structured data signing strictly binding verifyingContract address(this)
        bytes32 eip712Digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );
        return _verifySignature(eip712Digest, signature, attesterAuthority);
    }

    function _verifySignature(
        bytes32 hash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (expectedSigner == address(0)) return false;
        if (signature.length != 65) return false;

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
            return false;
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(hash, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
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

    function executeAttesterAuthority() external onlyOwner {
        if (pendingAttesterAuthority == address(0)) revert NoPendingAuthority();
        if (block.timestamp < authorityTimelockUnlock) revert AuthorityTimelockActive(block.timestamp, authorityTimelockUnlock);
        emit AttesterAuthorityUpdated(attesterAuthority, pendingAttesterAuthority);
        attesterAuthority = pendingAttesterAuthority;
        pendingAttesterAuthority = address(0);
        authorityTimelockUnlock = 0;
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

    function setGuardian(address _newGuardian) external onlyOwner {
        emit GuardianUpdated(guardian, _newGuardian);
        guardian = _newGuardian;
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
