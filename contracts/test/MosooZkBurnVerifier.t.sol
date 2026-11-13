// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "./MosooLocker.t.sol";
import "../MosooZkBurnVerifier.sol";

/// @dev Cryptographically binds (imageId, sha256(journal)) so any 1-bit flip in seal,
///      imageId, or journal reverts inside tests.
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    error InvalidRiscZeroSeal();

    function expectedSeal(bytes32 imageId, bytes32 journalDigest) external pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(imageId, journalDigest)));
    }

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external pure override {
        bytes32 expected = keccak256(abi.encode(imageId, journalDigest));
        if (seal.length != 32 || bytes32(seal) != expected) {
            revert InvalidRiscZeroSeal();
        }
    }
}

contract MosooZkBurnVerifierTest is Test {
    uint256 private constant ATTESTER1_PK = 0xA11CE;
    uint256 private constant ATTESTER2_PK = 0xB0B01;
    uint256 private constant GUARDIAN_PK = 0x60A9D;

    bytes32 private constant OUTBOUND_IMAGE_ID = keccak256("mosoo_outbound_burn_guest_v1");
    bytes32 private constant STATE_IMAGE_ID = keccak256("mosoo_lez_state_transition_guest_v1");
    bytes32 private constant SOURCE_INSTANCE = keccak256("CANONICAL_SEPOLIA_MOSOO_INSTANCE");
    bytes32 private constant GENESIS_ROOT = keccak256("lez_genesis_state_root_1");
    uint64 private constant GENESIS_SLOT = 81_000;

    MosooLocker private locker;
    MockRiscZeroVerifier private risc0;
    MosooZkBurnVerifier private zkVerifier;
    MockERC20 private token;

    address private attester1;
    address private attester2;
    address private guardian;
    address private user = address(0xCAFE01);

    function setUp() public {
        attester1 = vm.addr(ATTESTER1_PK);
        attester2 = vm.addr(ATTESTER2_PK);
        guardian = vm.addr(GUARDIAN_PK);

        locker = new MosooLocker(attester1, guardian);
        risc0 = new MockRiscZeroVerifier();

        address[] memory emptyCommittee = new address[](0);
        zkVerifier = new MosooZkBurnVerifier(
            address(risc0),
            OUTBOUND_IMAGE_ID,
            STATE_IMAGE_ID,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            GENESIS_SLOT,
            true, // zkStrictMode = true
            emptyCommittee,
            0
        );

        locker.setZkBurnVerifier(address(zkVerifier));

        token = new MockERC20();
        locker.setTokenAllowed(address(token), true);
        locker.setStandardDenomination(100 * 10 ** 18, true);

        vm.deal(address(this), 50 ether);
        vm.deal(user, 50 ether);
    }

    receive() external payable {}

    function _commissionDefault() internal {
        address[] memory add = new address[](1);
        add[0] = attester2;
        locker.commissionLocker(add, 2);
    }

    function _encodeBurnJournal(
        uint256 chainId,
        address lockerAddr,
        bytes32 sourceInstance,
        bytes32 lezStateRoot,
        bytes32 burnNullifier,
        address assetToken,
        address recipient,
        uint256 amount,
        uint64 lezSlot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            chainId,
            lockerAddr,
            sourceInstance,
            lezStateRoot,
            burnNullifier,
            assetToken,
            recipient,
            amount,
            lezSlot
        );
    }

    function _encodeStateJournal(
        uint256 chainId,
        address verifierAddr,
        bytes32 sourceInstance,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint64 prevSlot,
        uint64 newSlot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            chainId,
            verifierAddr,
            sourceInstance,
            prevRoot,
            newRoot,
            prevSlot,
            newSlot
        );
    }

    function test_zk_eth_state_advance_and_trustless_unlock() public {
        _commissionDefault();

        // 1. Shielded ETH deposit on Ethereum L1
        bytes32 depCommitment = keccak256("shielded_dep_1");
        vm.prank(user);
        locker.depositShieldedETH{value: 1 ether}(depCommitment);

        // 2. Permissionlessly advance LEZ state root using RISC Zero state-transition proof
        bytes32 root1 = keccak256("lez_state_root_81648");
        uint64 slot1 = 81_648;
        bytes memory stateJournal = _encodeStateJournal(
            block.chainid,
            address(zkVerifier),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            root1,
            GENESIS_SLOT,
            slot1
        );
        bytes memory stateSeal = risc0.expectedSeal(STATE_IMAGE_ID, sha256(stateJournal));
        zkVerifier.advanceLezStateRootWithProof(stateSeal, stateJournal);

        assertEq(zkVerifier.latestProvenRoot(), root1, "latest root updated");
        assertEq(uint256(zkVerifier.latestProvenSlot()), uint256(slot1), "latest slot updated");

        // ZK-02 regression: Competing stale/fork branch from GENESIS_ROOT MUST revert with NonCanonicalParentRoot
        bytes32 forkRoot = keccak256("lez_state_root_fork");
        bytes memory forkJournal = _encodeStateJournal(
            block.chainid,
            address(zkVerifier),
            SOURCE_INSTANCE,
            GENESIS_ROOT, // Stale parent root (canonical tip is already root1)
            forkRoot,
            GENESIS_SLOT,
            slot1
        );
        bytes memory forkSeal = risc0.expectedSeal(STATE_IMAGE_ID, sha256(forkJournal));
        try zkVerifier.advanceLezStateRootWithProof(forkSeal, forkJournal) {
            revert("competing stale/fork state transition MUST revert");
        } catch {}

        // 3. Trustless permissionless ETH unlock via ZK proof (NO attester signatures!)
        bytes32 nullifier1 = keccak256("burn_nullifier_eth_1");
        address recipient = address(0xBEEF01);
        bytes memory burnJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            root1,
            nullifier1,
            address(0),
            recipient,
            1 ether,
            slot1
        );
        bytes memory burnSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(burnJournal));

        uint256 balBefore = recipient.balance;
        locker.unlockShieldedWithZkProof(burnSeal, burnJournal);
        assertEq(recipient.balance - balBefore, 1 ether, "ZK ETH unlock must transfer 1 ETH");
        assertTrue(locker.executedBurns(nullifier1), "nullifier must be marked spent");
        assertEq(locker.totalLockedETH(), 0, "totalLockedETH updated");

        // 4. Replay MUST fail
        try locker.unlockShieldedWithZkProof(burnSeal, burnJournal) {
            revert("replayed ZK burn proof MUST fail");
        } catch {}

        // 5. Tampering 1 byte of journal (recipient/amount/root) MUST fail RISC Zero verification
        bytes memory tamperedJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            root1,
            keccak256("burn_nullifier_eth_2"),
            address(0),
            address(0xDEAD),
            1 ether,
            slot1
        );
        try locker.unlockShieldedWithZkProof(burnSeal, tamperedJournal) {
            revert("mismatched seal vs journal MUST fail");
        } catch {}
    }

    function test_zk_erc20_unlock_and_guardian_veto_and_large_queue() public {
        // Queue daily limit ETH/ERC20 pre-commission
        locker.setLargeWithdrawalThresholdERC20(address(token), 10_000 * 10 ** 18);
        token.mint(user, 500 * 10 ** 18);
        vm.prank(user);
        token.approve(address(locker), 500 * 10 ** 18);
        vm.prank(user);
        locker.depositShieldedERC20(address(token), 100 * 10 ** 18, keccak256("erc20_dep_1"));

        // Configure ERC20 daily limit before testing unlock
        locker.proposeDailyWithdrawalLimitERC20(address(token), 1_000 * 10 ** 18);
        uint256 delay = locker.GOVERNANCE_TIMELOCK_DELAY();
        vm.warp(block.timestamp + delay + 1);
        locker.executeDailyWithdrawalLimitERC20(address(token));

        _commissionDefault();

        bytes32 erc20Nullifier = keccak256("burn_nullifier_erc20_1");
        address recipient = address(0xBEEF02);
        bytes memory journal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            erc20Nullifier,
            address(token),
            recipient,
            100 * 10 ** 18,
            GENESIS_SLOT
        );
        bytes memory seal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(journal));

        locker.unlockShieldedWithZkProof(seal, journal);
        assertEq(token.balanceOf(recipient), 100 * 10 ** 18, "ZK ERC20 unlock succeeded");

        // Guardian veto permanently blocks even a valid ZK proof for cancelled nullifier
        vm.deal(user, 20 ether);
        vm.prank(user);
        locker.depositShieldedETH{value: 10 ether}(keccak256("shielded_large_eth"));

        bytes32 vetoedNullifier = keccak256("burn_nullifier_veto");
        vm.prank(guardian);
        locker.cancelBurn(vetoedNullifier);

        bytes memory vetoJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            vetoedNullifier,
            address(0),
            recipient,
            10 ether,
            GENESIS_SLOT
        );
        bytes memory vetoSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(vetoJournal));
        try locker.unlockShieldedWithZkProof(vetoSeal, vetoJournal) {
            revert("guardian-vetoed burn MUST revert even with valid ZK proof");
        } catch {}

        // Large ETH withdrawal >= 10 ether enforces mandatory 24h queue
        bytes32 largeNullifier = keccak256("burn_nullifier_large");
        bytes memory largeJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            largeNullifier,
            address(0),
            recipient,
            10 ether,
            GENESIS_SLOT
        );
        bytes memory largeSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(largeJournal));

        uint256 beforeBal = recipient.balance;
        locker.unlockShieldedWithZkProof(largeSeal, largeJournal);
        assertEq(recipient.balance, beforeBal, "first call must queue, not settle immediately");
        assertFalse(locker.executedBurns(largeNullifier), "queued burn MUST NOT be marked executed");
        assertTrue(locker.queuedWithdrawalUnlockTime(largeNullifier) > 0, "queued timestamp must be set");

        try locker.unlockShieldedWithZkProof(largeSeal, largeJournal) {
            revert("settling before 24h large queue delay MUST revert");
        } catch {}

        uint256 t1 = block.timestamp;
        vm.warp(t1 + 1 days + 1);
        locker.unlockShieldedWithZkProof(largeSeal, largeJournal);
        assertEq(recipient.balance - beforeBal, 10 ether, "large ZK withdrawal settles after 24h");
    }

    function test_zk_padding_domain_and_committee_fallback_boundaries() public {
        _commissionDefault();

        // 1. Direct setZkBurnVerifier MUST revert post-commissioning
        try locker.setZkBurnVerifier(address(zkVerifier)) {
            revert("direct setZkBurnVerifier must be blocked once commissioned");
        } catch {}

        // 2. Dirty upper padding bits in `journal` word 1 (locker) MUST revert InvalidJournalPadding
        bytes memory validJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            keccak256("nul_pad_test"),
            address(0),
            address(0xBEEF03),
            1 ether,
            GENESIS_SLOT
        );
        bytes memory dirtyJournal = new bytes(288);
        for (uint256 i = 0; i < 288; i++) {
            dirtyJournal[i] = validJournal[i];
        }
        dirtyJournal[32] = 0x01; // non-zero upper padding byte on address locker
        bytes memory dirtySeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(dirtyJournal));
        try locker.unlockShieldedWithZkProof(dirtySeal, dirtyJournal) {
            revert("dirty upper ABI padding on locker MUST revert");
        } catch {}

        // ZK-03 regression: Dirty upper padding on chainId (word 0, bytes 0..23) MUST revert
        dirtyJournal[32] = 0x00;
        dirtyJournal[0] = 0x01;
        dirtySeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(dirtyJournal));
        try locker.unlockShieldedWithZkProof(dirtySeal, dirtyJournal) {
            revert("dirty upper ABI padding on chainId MUST revert");
        } catch {}

        // ZK-03 regression: Dirty upper padding on amount (word 7, bytes 224..239) MUST revert
        dirtyJournal[0] = 0x00;
        dirtyJournal[224] = 0x01;
        dirtySeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(dirtyJournal));
        try locker.unlockShieldedWithZkProof(dirtySeal, dirtyJournal) {
            revert("dirty upper ABI padding on amount MUST revert");
        } catch {}

        // 3. Future slot claim (`lezSlot > rootSlot[lezStateRoot]`) MUST revert
        bytes memory futureJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            keccak256("nul_future_slot"),
            address(0),
            address(0xBEEF03),
            1 ether,
            GENESIS_SLOT + 1
        );
        bytes memory futureSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(futureJournal));
        try locker.unlockShieldedWithZkProof(futureSeal, futureJournal) {
            revert("future slot beyond proven root MUST revert");
        } catch {}

        // 4. Wrong sourceInstance MUST be rejected at L1 in both verifyOutboundBurn and advanceLezStateRootWithProof
        bytes32 wrongInstance = keccak256("ROGUE_INSTANCE");
        bytes memory rogueJournal = _encodeBurnJournal(
            block.chainid,
            address(locker),
            wrongInstance,
            GENESIS_ROOT,
            keccak256("nul_wrong_instance"),
            address(0),
            address(0xBEEF03),
            1 ether,
            GENESIS_SLOT
        );
        bytes memory rogueSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(rogueJournal));
        try locker.unlockShieldedWithZkProof(rogueSeal, rogueJournal) {
            revert("mismatched sourceInstance MUST revert at L1");
        } catch {}

        // 5. Transitional verifier prevents committee lineage laundering once zkStrictMode is enabled
        address[] memory committee = new address[](2);
        (address a1, address a2) = attester1 < attester2 ? (attester1, attester2) : (attester2, attester1);
        uint256 pk1 = attester1 < attester2 ? ATTESTER1_PK : ATTESTER2_PK;
        uint256 pk2 = attester1 < attester2 ? ATTESTER2_PK : ATTESTER1_PK;
        committee[0] = a1;
        committee[1] = a2;

        MosooZkBurnVerifier phasedVerifier = new MosooZkBurnVerifier(
            address(risc0),
            OUTBOUND_IMAGE_ID,
            STATE_IMAGE_ID,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            GENESIS_SLOT,
            false,
            committee,
            2
        );

        bytes32 ckRoot = keccak256("committee_ckpt_root");
        uint64 ckSlot = GENESIS_SLOT + 10;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                phasedVerifier.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(phasedVerifier.LEZ_STATE_ROOT_TYPEHASH(), SOURCE_INSTANCE, ckRoot, ckSlot))
            )
        );
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, digest);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = abi.encodePacked(r1, s1, v1);
        sigs[1] = abi.encodePacked(r2, s2, v2);
        phasedVerifier.registerCommitteeStateRoot(SOURCE_INSTANCE, ckRoot, ckSlot, sigs);
        assertTrue(phasedVerifier.acceptedLezStateRoots(ckRoot), "committee root registered in phased mode");
        assertFalse(phasedVerifier.isPureZkRoot(ckRoot), "committee root MUST NOT be marked pure ZK");

        // Advance ckRoot -> childRoot BEFORE zkStrictMode is enabled; childRoot must NOT launder lineage
        bytes32 childRoot = keccak256("child_of_committee_root");
        uint64 childSlot = ckSlot + 5;
        bytes memory childStateJournal = _encodeStateJournal(
            block.chainid,
            address(phasedVerifier),
            SOURCE_INSTANCE,
            ckRoot,
            childRoot,
            ckSlot,
            childSlot
        );
        bytes memory childStateSeal = risc0.expectedSeal(STATE_IMAGE_ID, sha256(childStateJournal));
        phasedVerifier.advanceLezStateRootWithProof(childStateSeal, childStateJournal);
        assertFalse(phasedVerifier.isPureZkRoot(childRoot), "descendant of committee root stays non-pure-ZK");

        // Enable strict ZK mode -> committee checkpoint registration AND childRoot burn verification MUST fail,
        // and latestProvenRoot MUST roll back from committee-tainted childRoot to latest pure ZK root (GENESIS_ROOT)
        phasedVerifier.enableZkStrictMode();
        assertEq(phasedVerifier.latestProvenRoot(), GENESIS_ROOT, "strict mode must restore latestPureZkRoot");
        assertEq(uint256(phasedVerifier.latestProvenSlot()), uint256(GENESIS_SLOT), "strict mode must restore latestPureZkSlot");
        phasedVerifier.enableZkStrictMode();
        try phasedVerifier.registerCommitteeStateRoot(SOURCE_INSTANCE, keccak256("root_after_strict"), childSlot + 1, sigs) {
            revert("registerCommitteeStateRoot MUST revert once zkStrictMode is enabled");
        } catch {}
        bytes memory launderedBurn = _encodeBurnJournal(
            block.chainid,
            address(locker),
            SOURCE_INSTANCE,
            childRoot,
            keccak256("nul_laundered"),
            address(0),
            address(0xBEEF03),
            1 ether,
            childSlot
        );
        bytes memory launderedSeal = risc0.expectedSeal(OUTBOUND_IMAGE_ID, sha256(launderedBurn));
        try phasedVerifier.verifyOutboundBurn(launderedSeal, launderedBurn) {
            revert("committee lineage descendant MUST revert under zkStrictMode");
        } catch {}
    }

    function test_zk_verifier_timelock_governance_and_guardian_cancel() public {
        _commissionDefault();
        address[] memory empty = new address[](0);
        MosooZkBurnVerifier nextVerifier = new MosooZkBurnVerifier(
            address(risc0),
            OUTBOUND_IMAGE_ID,
            STATE_IMAGE_ID,
            address(locker),
            SOURCE_INSTANCE,
            GENESIS_ROOT,
            GENESIS_SLOT,
            true,
            empty,
            0
        );

        locker.proposeZkBurnVerifier(address(nextVerifier));
        try locker.executeZkBurnVerifier() {
            revert("executeZkBurnVerifier before 2-day timelock MUST revert");
        } catch {}

        // Guardian cancels via actionType 12
        vm.prank(guardian);
        locker.cancelPendingGovernance(12);

        uint256 govDelay = locker.GOVERNANCE_TIMELOCK_DELAY();
        uint256 t0 = block.timestamp;
        vm.warp(t0 + govDelay + 1);
        try locker.executeZkBurnVerifier() {
            revert("cancelled zkBurnVerifier proposal MUST revert");
        } catch {}

        // Re-propose and execute after timelock
        locker.proposeZkBurnVerifier(address(nextVerifier));
        vm.warp(t0 + 2 * govDelay + 2);
        locker.executeZkBurnVerifier();
        assertEq(locker.zkBurnVerifier(), address(nextVerifier), "zkBurnVerifier upgraded after timelock");
    }
}
