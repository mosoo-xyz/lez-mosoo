// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title MosooLocker
 * @notice Canonical Ethereum Escrow and Settlement contract for the Mosoo Light Client Bridge
 *         connecting Ethereum (Mainnet / Sepolia / Holesky) and the Logos Execution Zone (LEZ).
 *
 * @dev Architecture & Security:
 * 1. Deposits on Ethereum lock native ETH or ERC-20 tokens in this contract, emitting verifiable
 *    receipt logs that are cryptographically verified by the Mosoo zkVM light client on LEZ.
 * 2. Successful verification allows minting synthetic `mETH` on LEZ with a 1:1 backing guarantee.
 * 3. When a user burns `mETH` on LEZ, an on-chain `BurnReceipt` is produced.
 * 4. The user (or relayer) presents this burn proof to `unlockETH`, releasing locked ETH.
 * 5. Replay attacks are strictly prevented on Ethereum using the `executedBurns` nullifier mapping.
 */
contract MosooLocker {
    // --- State Variables ---

    address public owner;
    address public attesterAuthority;
    bool public paused;

    uint256 public totalLockedETH;
    uint256 public totalUnlockedETH;
    uint64 public depositNonce;

    /// @notice Nullifier registry preventing cross-chain burn replay attacks
    mapping(bytes32 => bool) public executedBurns;

    /// @notice ERC-20 token deposit accounting: token => total locked
    mapping(address => uint256) public totalLockedERC20;

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
        uint64 indexed nonce
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
    event PausedStateChanged(bool isPaused);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // --- Errors ---

    error ZeroAmount();
    error ZeroAddress();
    error ContractPaused();
    error Unauthorized();
    error ReentrancyGuardReentrantCall();
    error BurnAlreadyExecuted();
    error InvalidBurnProof();
    error InsufficientLockedETH();
    error ETHTransferFailed();
    error ERC20TransferFailed();

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
        _status = _NOT_ENTERED;
        emit OwnershipTransferred(address(0), msg.sender);
        emit AttesterAuthorityUpdated(address(0), _attesterAuthority);
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

        depositNonce += 1;
        nonce = depositNonce;
        totalLockedERC20[token] += amount;

        // Low-level safeTransferFrom to support diverse ERC-20 implementations
        bytes memory data = abi.encodeWithSelector(0x23b87266, msg.sender, address(this), amount);
        (bool success, bytes memory returnData) = token.call(data);
        if (!success || (returnData.length != 0 && !abi.decode(returnData, (bool)))) {
            revert ERC20TransferFailed();
        }

        emit DepositERC20(token, msg.sender, lezRecipient, amount, nonce);
    }

    // --- Unlock Functions (LEZ -> ETH) ---

    /**
     * @notice Release locked native ETH back to an Ethereum address upon verifiable burn on LEZ.
     * @param burnId The cryptographic identifier of the burn receipt on LEZ.
     * @param amount The amount of ETH (in wei) to unlock.
     * @param recipient The Ethereum recipient address receiving the unlocked ETH.
     * @param lezOwner The LEZ account that performed the burn.
     * @param burnNonce The sequential burn counter from the LEZ bridge.
     * @param lezSlot The LEZ block/slot height at which the burn occurred.
     * @param attestationSignature Cryptographic signature from the attester authority or ZK proof.
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
        if (address(this).balance < amount) revert InsufficientLockedETH();

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

        // 2. Verify attestation signature over burnId
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", burnId)
        );
        if (!_verifySignature(ethSignedMessageHash, attestationSignature, attesterAuthority)) {
            revert InvalidBurnProof();
        }

        // 3. Mark burn nullifier as spent (prevents replay)
        executedBurns[burnId] = true;
        totalUnlockedETH += amount;
        totalLockedETH -= amount;

        // 4. Transfer ETH to recipient
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();

        emit UnlockedETH(burnId, recipient, amount, lezSlot);
    }

    // --- Internal Helpers ---

    function _verifySignature(
        bytes32 hash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        return ecrecover(hash, v, r, s) == expectedSigner;
    }

    // --- Admin Functions ---

    function setAttesterAuthority(address _newAuthority) external onlyOwner {
        if (_newAuthority == address(0)) revert ZeroAddress();
        emit AttesterAuthorityUpdated(attesterAuthority, _newAuthority);
        attesterAuthority = _newAuthority;
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedStateChanged(_paused);
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    // --- Receive Fallback ---
    receive() external payable {
        // Direct transfers not permitted to prevent unindexed deposits
        revert Unauthorized();
    }
}
