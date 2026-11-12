// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IRiscZeroVerifier
 * @notice Canonical RISC Zero verifier interface matching risc0-ethereum's
 *         RiscZeroVerifierRouter / RiscZeroGroth16Verifier.
 */
interface IRiscZeroVerifier {
    /// @notice Verifies that `seal` is a valid zkVM receipt for `imageId` and `journalDigest = sha256(journal)`.
    /// @dev Must revert if verification fails.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/**
 * @title IMosooZkBurnVerifier
 * @notice Minimal verifier interface called by MosooLocker.unlockShieldedWithZkProof.
 */
interface IMosooZkBurnVerifier {
    function verifyOutboundBurn(bytes calldata seal, bytes calldata journal)
        external
        view
        returns (
            bytes32 burnNullifier,
            bytes32 sourceInstance,
            address assetToken,
            address recipient,
            uint256 amount
        );
}

/**
 * @title MosooZkBurnVerifier
 * @notice Trustless RISC Zero proof verifier for Mosoo RFP-022 outbound withdrawals (LEZ -> Ethereum).
 *
 * @dev Verifies:
 *   1. Permissionless chained LEZ finality / state-root progression via RISC Zero (`lezStateTransitionImageId`).
 *   2. Outbound shielded burn inclusion + nullifier derivation via RISC Zero (`outboundBurnImageId`)
 *      without revealing the LEZ burner's address, nonce, or burn secret in the public journal.
 *   3. Exact 1-to-1 canonical ABI encoding (288-byte burn journal, 224-byte state journal) preventing
 *      dirty-upper-bit journal malleability across `sha256(journal)`.
 *   4. Optional transitional M-of-N committee checkpoint seeding when `zkStrictMode == false`, which
 *      can be permanently locked off via `enableZkStrictMode()`.
 */
contract MosooZkBurnVerifier is IMosooZkBurnVerifier {
    enum RootOrigin {
        None,
        Genesis,
        ZkStateTransition,
        CommitteeCheckpoint
    }

    uint256 private constant OUTBOUND_BURN_JOURNAL_LEN = 288;
    uint256 private constant STATE_TRANSITION_JOURNAL_LEN = 224;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant LEZ_STATE_ROOT_TYPEHASH = keccak256(
        "LezStateRoot(bytes32 sourceInstance,bytes32 lezStateRoot,uint64 lezSlot)"
    );

    IRiscZeroVerifier public immutable riscZeroVerifier;
    bytes32 public immutable outboundBurnImageId;
    bytes32 public immutable lezStateTransitionImageId;
    address public immutable locker;
    uint256 public immutable boundChainId;
    bytes32 public immutable expectedSourceInstance;
    bytes32 public immutable genesisLezStateRoot;

    address public owner;
    bool public zkStrictMode;

    bytes32 public latestProvenRoot;
    uint64 public latestProvenSlot;
    bytes32 public latestPureZkRoot;
    uint64 public latestPureZkSlot;

    mapping(bytes32 => bool) public acceptedLezStateRoots;
    mapping(bytes32 => RootOrigin) public rootOrigin;
    mapping(bytes32 => bool) public isPureZkRoot;
    mapping(bytes32 => uint64) public rootSlot;

    // Optional committee checkpointing when zkStrictMode == false
    mapping(address => bool) public isAttester;
    uint256 public requiredQuorum;

    event LezStateRootAdvanced(
        bytes32 indexed sourceInstance,
        bytes32 indexed prevStateRoot,
        bytes32 indexed newStateRoot,
        uint64 prevSlot,
        uint64 newSlot,
        address submitter
    );
    event CommitteeStateRootRegistered(
        bytes32 indexed sourceInstance,
        bytes32 indexed lezStateRoot,
        uint64 lezSlot
    );
    event ZkStrictModeEnabled(address indexed by);

    error ZeroAddress();
    error InvalidImageId();
    error InvalidJournalLength();
    error InvalidJournalPadding();
    error InvalidChainBinding();
    error InvalidLockerBinding();
    error InvalidSourceInstance();
    error InvalidNullifier();
    error ZeroAmount();
    error InvalidStateRoot();
    error UnknownPreviousRoot();
    error InvalidSlotProgression();
    error ZkStrictModeActive();
    error Unauthorized();
    error InvalidQuorumSignatures();

    constructor(
        address _riscZeroVerifier,
        bytes32 _outboundBurnImageId,
        bytes32 _lezStateTransitionImageId,
        address _locker,
        bytes32 _expectedSourceInstance,
        bytes32 _genesisLezStateRoot,
        uint64 _genesisSlot,
        bool _zkStrictMode,
        address[] memory _committeeAttesters,
        uint256 _requiredQuorum
    ) {
        if (_riscZeroVerifier == address(0) || _riscZeroVerifier.code.length == 0) revert ZeroAddress();
        if (_locker == address(0)) revert ZeroAddress();
        if (_expectedSourceInstance == bytes32(0)) revert InvalidSourceInstance();
        if (_outboundBurnImageId == bytes32(0) || _lezStateTransitionImageId == bytes32(0)) {
            revert InvalidImageId();
        }
        if (_genesisLezStateRoot == bytes32(0)) revert InvalidStateRoot();

        riscZeroVerifier = IRiscZeroVerifier(_riscZeroVerifier);
        outboundBurnImageId = _outboundBurnImageId;
        lezStateTransitionImageId = _lezStateTransitionImageId;
        locker = _locker;
        boundChainId = block.chainid;
        expectedSourceInstance = _expectedSourceInstance;
        genesisLezStateRoot = _genesisLezStateRoot;
        owner = msg.sender;
        zkStrictMode = _zkStrictMode;

        acceptedLezStateRoots[_genesisLezStateRoot] = true;
        rootOrigin[_genesisLezStateRoot] = RootOrigin.Genesis;
        isPureZkRoot[_genesisLezStateRoot] = true;
        rootSlot[_genesisLezStateRoot] = _genesisSlot;
        latestProvenRoot = _genesisLezStateRoot;
        latestProvenSlot = _genesisSlot;
        latestPureZkRoot = _genesisLezStateRoot;
        latestPureZkSlot = _genesisSlot;

        if (!_zkStrictMode && _committeeAttesters.length > 0) {
            if (_requiredQuorum == 0 || _requiredQuorum > _committeeAttesters.length) {
                revert InvalidQuorumSignatures();
            }
            for (uint256 i = 0; i < _committeeAttesters.length; i++) {
                address att = _committeeAttesters[i];
                if (att == address(0) || isAttester[att]) revert InvalidQuorumSignatures();
                isAttester[att] = true;
            }
            requiredQuorum = _requiredQuorum;
        }
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("MosooZkBurnVerifier")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Permanently disable committee-checkpoint roots and enforce 100% ZK state transitions.
    function enableZkStrictMode() external {
        if (msg.sender != owner) revert Unauthorized();
        zkStrictMode = true;
        if (!isPureZkRoot[latestProvenRoot]) {
            latestProvenRoot = latestPureZkRoot;
            latestProvenSlot = latestPureZkSlot;
        }
        emit ZkStrictModeEnabled(msg.sender);
    }

    /// @notice Permissionlessly advance the accepted LEZ state root using a RISC Zero validity proof.
    function advanceLezStateRootWithProof(bytes calldata stateSeal, bytes calldata stateJournal) external {
        if (stateJournal.length != STATE_TRANSITION_JOURNAL_LEN) revert InvalidJournalLength();
        // Verify canonical upper-zero padding for `address verifier` (word 1), `uint64 prevSlot` (word 5), and `uint64 newSlot` (word 6).
        if (
            !_hasZeroPrefix(stateJournal, 32, 12)
                || !_hasZeroPrefix(stateJournal, 160, 24)
                || !_hasZeroPrefix(stateJournal, 192, 24)
        ) {
            revert InvalidJournalPadding();
        }

        (
            uint256 chainId,
            address verifierAddr,
            bytes32 sourceInstance,
            bytes32 prevStateRoot,
            bytes32 newStateRoot,
            uint64 prevSlot,
            uint64 newSlot
        ) = abi.decode(stateJournal, (uint256, address, bytes32, bytes32, bytes32, uint64, uint64));

        if (chainId != block.chainid || chainId != boundChainId) revert InvalidChainBinding();
        if (verifierAddr != address(this)) revert InvalidLockerBinding();
        if (sourceInstance != expectedSourceInstance) revert InvalidSourceInstance();
        if (!acceptedLezStateRoots[prevStateRoot]) revert UnknownPreviousRoot();
        bool parentPureZk = isPureZkRoot[prevStateRoot];
        if (zkStrictMode && !parentPureZk) {
            revert ZkStrictModeActive();
        }
        if (newStateRoot == bytes32(0) || newStateRoot == prevStateRoot) revert InvalidStateRoot();
        if (prevSlot != rootSlot[prevStateRoot] || newSlot <= prevSlot) revert InvalidSlotProgression();
        if (acceptedLezStateRoots[newStateRoot]) revert InvalidStateRoot();

        riscZeroVerifier.verify(stateSeal, lezStateTransitionImageId, sha256(stateJournal));

        acceptedLezStateRoots[newStateRoot] = true;
        rootOrigin[newStateRoot] = RootOrigin.ZkStateTransition;
        isPureZkRoot[newStateRoot] = parentPureZk;
        rootSlot[newStateRoot] = newSlot;
        if (parentPureZk && newSlot > latestPureZkSlot) {
            latestPureZkRoot = newStateRoot;
            latestPureZkSlot = newSlot;
        }
        if (newSlot > latestProvenSlot) {
            latestProvenRoot = newStateRoot;
            latestProvenSlot = newSlot;
        }

        emit LezStateRootAdvanced(sourceInstance, prevStateRoot, newStateRoot, prevSlot, newSlot, msg.sender);
    }

    /// @notice Transitional M-of-N committee checkpoint registration (permanently blocked once `zkStrictMode == true`).
    function registerCommitteeStateRoot(
        bytes32 sourceInstance,
        bytes32 lezStateRoot,
        uint64 lezSlot,
        bytes[] calldata signatures
    ) external {
        if (zkStrictMode || requiredQuorum == 0) revert ZkStrictModeActive();
        if (sourceInstance != expectedSourceInstance) revert InvalidSourceInstance();
        if (lezStateRoot == bytes32(0) || acceptedLezStateRoots[lezStateRoot]) revert InvalidStateRoot();
        if (lezSlot == 0 || lezSlot <= latestProvenSlot) revert InvalidSlotProgression();
        if (signatures.length < requiredQuorum) revert InvalidQuorumSignatures();

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(LEZ_STATE_ROOT_TYPEHASH, sourceInstance, lezStateRoot, lezSlot))
            )
        );

        address lastSigner = address(0);
        uint256 validCount = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(digest, signatures[i]);
            if (signer == address(0) || !isAttester[signer] || signer <= lastSigner) {
                revert InvalidQuorumSignatures();
            }
            lastSigner = signer;
            validCount++;
            if (validCount >= requiredQuorum) break;
        }
        if (validCount < requiredQuorum) revert InvalidQuorumSignatures();

        acceptedLezStateRoots[lezStateRoot] = true;
        rootOrigin[lezStateRoot] = RootOrigin.CommitteeCheckpoint;
        rootSlot[lezStateRoot] = lezSlot;
        latestProvenRoot = lezStateRoot;
        latestProvenSlot = lezSlot;

        emit CommitteeStateRootRegistered(sourceInstance, lezStateRoot, lezSlot);
    }

    /// @inheritdoc IMosooZkBurnVerifier
    function verifyOutboundBurn(bytes calldata seal, bytes calldata journal)
        external
        view
        returns (
            bytes32 burnNullifier,
            bytes32 sourceInstance,
            address assetToken,
            address recipient,
            uint256 amount
        )
    {
        if (journal.length != OUTBOUND_BURN_JOURNAL_LEN) revert InvalidJournalLength();
        // Verify canonical upper-zero padding on word 1 (locker), word 5 (assetToken), word 6 (recipient), and word 8 (uint64 lezSlot).
        if (
            !_hasZeroPrefix(journal, 32, 12)
                || !_hasZeroPrefix(journal, 160, 12)
                || !_hasZeroPrefix(journal, 192, 12)
                || !_hasZeroPrefix(journal, 256, 24)
        ) {
            revert InvalidJournalPadding();
        }

        uint256 chainId;
        address lockerAddr;
        bytes32 lezStateRoot;
        uint64 lezSlot;

        (
            chainId,
            lockerAddr,
            sourceInstance,
            lezStateRoot,
            burnNullifier,
            assetToken,
            recipient,
            amount,
            lezSlot
        ) = abi.decode(
            journal,
            (uint256, address, bytes32, bytes32, bytes32, address, address, uint256, uint64)
        );

        if (chainId != block.chainid || chainId != boundChainId) revert InvalidChainBinding();
        if (lockerAddr != locker) revert InvalidLockerBinding();
        if (sourceInstance != expectedSourceInstance) revert InvalidSourceInstance();
        if (burnNullifier == bytes32(0)) revert InvalidNullifier();
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (!acceptedLezStateRoots[lezStateRoot]) revert InvalidStateRoot();
        if (zkStrictMode && !isPureZkRoot[lezStateRoot]) {
            revert ZkStrictModeActive();
        }
        if (lezSlot == 0 || lezSlot > rootSlot[lezStateRoot]) revert InvalidSlotProgression();

        riscZeroVerifier.verify(seal, outboundBurnImageId, sha256(journal));
    }

    function _hasZeroPrefix(bytes calldata data, uint256 offset, uint256 prefixLen) private pure returns (bool) {
        for (uint256 i = 0; i < prefixLen; i++) {
            if (data[offset + i] != 0) return false;
        }
        return true;
    }

    function _recoverSigner(bytes32 hash, bytes memory signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}
