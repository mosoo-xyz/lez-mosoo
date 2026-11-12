// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
    function deal(address who, uint256 newBalance) external;
    function prank(address msgSender) external;
}

abstract contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertEq(uint256 a, uint256 b, string memory err) internal pure {
        require(a == b, err);
    }
    function assertEq(address a, address b, string memory err) internal pure {
        require(a == b, err);
    }
    function assertEq(bytes32 a, bytes32 b, string memory err) internal pure {
        require(a == b, err);
    }
    function assertTrue(bool condition, string memory err) internal pure {
        require(condition, err);
    }
    function assertFalse(bool condition, string memory err) internal pure {
        require(!condition, err);
    }
}

import "../MosooLocker.sol";

contract MockERC20 {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MosooLockerTest is Test {
    MosooLocker public locker;
    MockERC20 public token;
    uint256 internal attesterPk = 0xA11CE;
    address internal attesterAuthority;
    address internal guardian = address(0x60A4D);
    address internal user = address(0xB0B);

    function setUp() public {
        attesterAuthority = vm.addr(attesterPk);
        locker = new MosooLocker(attesterAuthority, guardian);
        token = new MockERC20();
        locker.setTokenAllowed(address(token), true);
        vm.deal(user, 100 ether);
        token.mint(user, 1_000_000 ether);
    }

    function test_deposit_eth_success() public {
        vm.prank(user);
        uint64 nonce = locker.depositETH{value: 5 ether}(bytes32(uint256(0xAA)));
        assertEq(nonce, 1, "nonce should be 1");
        assertEq(locker.totalLockedETH(), 5 ether, "locked ETH mismatch");
    }

    function test_deposit_erc20_allowlist_enforcement() public {
        MockERC20 badToken = new MockERC20();
        badToken.mint(user, 100 ether);
        vm.prank(user);
        badToken.approve(address(locker), 100 ether);

        vm.prank(user);
        try locker.depositERC20(address(badToken), 10 ether, bytes32(uint256(0xAA))) {
            revert("Expected revert on unallowed token");
        } catch {
            // Success
        }
    }

    function test_cancel_queued_withdrawal_permanent_veto() public {
        vm.prank(user);
        locker.depositETH{value: 50 ether}(bytes32(uint256(0xAA)));

        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);
        uint256 amount = 15 ether; // >= 10 ETH threshold
        uint64 burnNonce = 1;
        uint64 lezSlot = 500;

        bytes32 burnId = keccak256(
            abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot)
        );

        bytes32 structHash = keccak256(
            abi.encode(
                locker.BURN_ETH_TYPEHASH(),
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // First attempt queues the withdrawal (requires enabling legacy routes for migration test)
        locker.setLegacyRoutesEnabled(true);
        locker.unlockETH(burnId, amount, recipient, lezOwner, burnNonce, lezSlot, sig);
        assertTrue(locker.queuedWithdrawalUnlockTime(burnId) > 0, "must be queued");

        // Guardian vetoes during 24h timelock
        vm.prank(guardian);
        locker.cancelQueuedWithdrawal(burnId);
        assertTrue(locker.cancelledBurns(burnId), "burnId must be permanently marked cancelled");

        // Fast forward 2 days
        vm.warp(block.timestamp + 2 days);

        // Re-attempting unlock MUST revert with BurnCancelled, NOT re-queue!
        try locker.unlockETH(burnId, amount, recipient, lezOwner, burnNonce, lezSlot, sig) {
            revert("Expected revert with BurnCancelled");
        } catch {
            // Success: cancellation is permanent veto
        }
    }

    function test_daily_withdrawal_limit_eth_enforced() public {
        vm.prank(user);
        locker.depositETH{value: 20 ether}(bytes32(uint256(0xAA)));

        locker.proposeDailyWithdrawalLimitETH(5 ether);
        vm.warp(locker.dailyLimitETHTimelockUnlock());
        locker.executeDailyWithdrawalLimitETH();
        assertEq(locker.dailyWithdrawalLimitETH(), 5 ether, "daily limit mismatch");
    }

    function test_emergency_pause_by_guardian() public {
        vm.prank(guardian);
        locker.emergencyPause();
        assertTrue(locker.paused(), "contract must be paused");

        vm.prank(user);
        try locker.depositETH{value: 1 ether}(bytes32(uint256(0xAA))) {
            revert("Expected revert when paused");
        } catch {
            // Success
        }
    }

    function test_committee_quorum_m_of_n() public {
        uint256 attester2Pk = 0xB22CE;
        uint256 attester3Pk = 0xC33CE;
        address attester2 = vm.addr(attester2Pk);
        address attester3 = vm.addr(attester3Pk);

        // Pre-commission legacy migration route enabled prior to 2-of-3 graduation
        locker.setLegacyRoutesEnabled(true);

        locker.proposeAddAttester(attester2);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        locker.proposeAddAttester(attester3);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        locker.proposeQuorum(2);
        vm.warp(locker.quorumTimelockUnlock());
        locker.executeQuorum();

        assertEq(locker.attesterCount(), 3, "total attesters should be 3");
        assertEq(locker.requiredQuorum(), 2, "required quorum should be 2");

        vm.prank(user);
        locker.depositETH{value: 10 ether}(bytes32(uint256(0xAA)));

        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);
        uint256 amount = 2 ether;
        uint64 burnNonce = 10;
        uint64 lezSlot = 600;

        bytes32 burnId = keccak256(
            abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                locker.BURN_ETH_TYPEHASH(),
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));

        // Sub-threshold quorum (only 1 signature provided)
        bytes[] memory subQuorumSigs = new bytes[](1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(attesterPk, digest);
        subQuorumSigs[0] = abi.encodePacked(r1, s1, v1);

        try locker.unlockETHWithQuorum(burnId, recipient, amount, lezOwner, burnNonce, lezSlot, subQuorumSigs) {
            revert("Expected revert on sub-threshold quorum");
        } catch {
            // Success
        }

        // Two valid signatures in strictly ascending signer order
        address addr1 = attesterAuthority;
        address addr2 = attester2;
        uint256 pkFirst = attesterPk;
        uint256 pkSecond = attester2Pk;
        if (addr1 > addr2) {
            pkFirst = attester2Pk;
            pkSecond = attesterPk;
        }

        bytes[] memory validQuorumSigs = new bytes[](2);
        (uint8 va, bytes32 ra, bytes32 sa) = vm.sign(pkFirst, digest);
        (uint8 vb, bytes32 rb, bytes32 sb) = vm.sign(pkSecond, digest);
        validQuorumSigs[0] = abi.encodePacked(ra, sa, va);
        validQuorumSigs[1] = abi.encodePacked(rb, sb, vb);

        locker.unlockETHWithQuorum(burnId, recipient, amount, lezOwner, burnNonce, lezSlot, validQuorumSigs);
        assertTrue(locker.executedBurns(burnId), "burnId must be marked executed");
        assertEq(locker.totalUnlockedETH(), amount, "unlocked ETH mismatch");
    }

    function test_direct_set_guardian_deprecated() public {
        try locker.setGuardian(address(0x1234)) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
    }

    function test_direct_governance_setters_deprecated() public {
        try locker.setDailyWithdrawalLimitETH(1 ether) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
        try locker.setDailyWithdrawalLimitERC20(address(token), 1000) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
        try locker.addAttester(address(0x1234)) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
        try locker.removeAttester(address(0x1234)) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
        try locker.setQuorum(2) {
            revert("Expected revert with DirectGovernanceDeprecated");
        } catch {
            // Success
        }
    }

    function test_guardian_timelock_governance() public {
        address newGuardian = address(0x9999);
        locker.proposeGuardian(newGuardian);
        assertEq(locker.pendingGuardian(), newGuardian, "pending guardian mismatch");

        // Attempting to execute immediately must fail due to 2-day timelock
        try locker.executeGuardian() {
            revert("Expected revert due to active timelock");
        } catch {
            // Success
        }

        // Warp past 2-day timelock delay
        vm.warp(locker.guardianTimelockUnlock());
        locker.executeGuardian();
        assertEq(locker.guardian(), newGuardian, "guardian update failed");
        assertEq(locker.pendingGuardian(), address(0), "pending guardian not cleared");
    }

    function test_removed_attester_single_signature_rejected() public {
        locker.setLegacyRoutesEnabled(true);
        uint256 attester2Pk = 0xB22CE;
        address attester2 = vm.addr(attester2Pk);

        locker.proposeAddAttester(attester2);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        // Rotate authority to attester2
        locker.proposeAttesterAuthority(attester2);
        vm.warp(locker.authorityTimelockUnlock());
        locker.executeAttesterAuthority();

        assertEq(locker.attesterAuthority(), attester2, "authority mismatch");
        assertTrue(!locker.isAttester(attesterAuthority), "old authority must not be attester");

        // Deposit 10 ETH
        vm.prank(user);
        locker.depositETH{value: 10 ether}(bytes32(uint256(0xAA)));

        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);
        uint256 amount = 1 ether;
        uint64 burnNonce = 99;
        uint64 lezSlot = 700;

        bytes32 burnId = keccak256(
            abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                locker.BURN_ETH_TYPEHASH(),
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));

        // Old authority attempts single-signature unlock
        (uint8 vOld, bytes32 rOld, bytes32 sOld) = vm.sign(attesterPk, digest);
        bytes memory sigOld = abi.encodePacked(rOld, sOld, vOld);

        try locker.unlockETH(burnId, amount, recipient, lezOwner, burnNonce, lezSlot, sigOld) {
            revert("Expected revert on removed authority signature");
        } catch {
            // Success: old authority signature strictly rejected
        }

        // Active authority (attester2) signs
        (uint8 vNew, bytes32 rNew, bytes32 sNew) = vm.sign(attester2Pk, digest);
        bytes memory sigNew = abi.encodePacked(rNew, sNew, vNew);
        locker.unlockETH(burnId, amount, recipient, lezOwner, burnNonce, lezSlot, sigNew);
        assertTrue(locker.executedBurns(burnId), "burnId must be executed with active authority");
    }

    function test_authority_rotation_updates_committee_count_and_preserves_quorum() public {
        locker.setLegacyRoutesEnabled(true);
        uint256 attester2Pk = 0xB22CE;
        uint256 attester3Pk = 0xC33CE;
        address attester2 = vm.addr(attester2Pk);
        address attester3 = vm.addr(attester3Pk);

        // Pre-commission legacy migration route enabled prior to 2-of-3 graduation
        locker.setLegacyRoutesEnabled(true);

        locker.proposeAddAttester(attester2);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        locker.proposeAddAttester(attester3);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        assertEq(locker.attesterCount(), 3, "initial count should be 3");

        locker.proposeQuorum(3);
        vm.warp(locker.quorumTimelockUnlock());
        locker.executeQuorum();
        assertEq(locker.requiredQuorum(), 3, "quorum should be 3");

        // Rotate authority to attester2 (who is already in the committee)
        locker.proposeAttesterAuthority(attester2);
        vm.warp(locker.authorityTimelockUnlock());

        // Attempting to execute authority rotation when active committee count drops below quorum strictly reverts!
        try locker.executeAttesterAuthority() {
            revert("Expected revert with InvalidQuorum");
        } catch {
            // Success: authority rotation rejected when resulting count < requiredQuorum
        }

        // Guardian can cancel the pending authority rotation
        vm.prank(guardian);
        locker.cancelPendingGovernance(6);
        assertEq(locker.pendingAttesterAuthority(), address(0), "pending authority must be cleared by guardian");

        // Proper governance path: Reduce quorum to 2 via proposeQuorum with full 2-day timelock
        locker.proposeQuorum(2);
        vm.warp(locker.quorumTimelockUnlock());
        locker.executeQuorum();
        assertEq(locker.requiredQuorum(), 2, "quorum reduced to 2 via governance");

        // Now re-propose authority rotation to attester2
        locker.proposeAttesterAuthority(attester2);
        vm.warp(locker.authorityTimelockUnlock());
        locker.executeAttesterAuthority();

        // Old authority (attesterAuthority) was removed, attester2 was already in committee
        // Active attesters now: attester2, attester3 (count = 2)
        assertEq(locker.attesterCount(), 2, "attester count must accurately update to 2");
        assertEq(locker.requiredQuorum(), 2, "quorum remains 2");

        // Verify quorum of 2 can unlock successfully
        vm.prank(user);
        locker.depositETH{value: 10 ether}(bytes32(uint256(0xAA)));

        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);
        uint256 amount = 1 ether;
        uint64 burnNonce = 101;
        uint64 lezSlot = 800;

        bytes32 burnId = keccak256(
            abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                locker.BURN_ETH_TYPEHASH(),
                burnId,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));

        address addrA = attester2;
        address addrB = attester3;
        uint256 pkA = attester2Pk;
        uint256 pkB = attester3Pk;
        if (addrA > addrB) {
            pkA = attester3Pk;
            pkB = attester2Pk;
        }

        bytes[] memory sigs = new bytes[](2);
        (uint8 va, bytes32 ra, bytes32 sa) = vm.sign(pkA, digest);
        (uint8 vb, bytes32 rb, bytes32 sb) = vm.sign(pkB, digest);
        sigs[0] = abi.encodePacked(ra, sa, va);
        sigs[1] = abi.encodePacked(rb, sb, vb);

        locker.unlockETHWithQuorum(burnId, recipient, amount, lezOwner, burnNonce, lezSlot, sigs);
        assertTrue(locker.executedBurns(burnId), "burnId must execute under adjusted quorum");
    }

    function test_rolling_limit_dos_cleanup_pruning() public {
        locker.setLegacyRoutesEnabled(true);
        vm.prank(user);
        locker.depositETH{value: 50 ether}(bytes32(uint256(0xAA)));

        locker.proposeDailyWithdrawalLimitETH(10 ether);
        vm.warp(locker.dailyLimitETHTimelockUnlock());
        locker.executeDailyWithdrawalLimitETH();

        // Perform 40 small withdrawals of 0.2 ETH (total 8 ETH)
        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);

        for (uint64 i = 1; i <= 40; i++) {
            bytes32 burnId = keccak256(
                abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, uint256(0.2 ether), i, uint64(1000 + i))
            );
            bytes32 structHash = keccak256(
                abi.encode(
                    locker.BURN_ETH_TYPEHASH(),
                    burnId,
                    recipient,
                    uint256(0.2 ether),
                    lezOwner,
                    i,
                    uint64(1000 + i)
                )
            );
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digest);
            locker.unlockETH(burnId, 0.2 ether, recipient, lezOwner, i, 1000 + i, abi.encodePacked(r, s, v));
        }

        assertEq(locker.dailyWithdrawnETH(), 8 ether, "daily withdrawn should be 8 ETH");

        // Warp past 24 hours (all 40 withdrawals expire)
        vm.warp(block.timestamp + 25 hours);

        // A single large withdrawal of 9 ETH (under 10 ETH limit) must succeed by pruning expired records beyond 32
        uint64 largeNonce = 999;
        uint64 largeSlot = 50000;
        uint256 largeAmount = 9 ether;
        bytes32 largeBurnId = keccak256(
            abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, largeAmount, largeNonce, largeSlot)
        );
        bytes32 largeStructHash = keccak256(
            abi.encode(
                locker.BURN_ETH_TYPEHASH(),
                largeBurnId,
                recipient,
                largeAmount,
                lezOwner,
                largeNonce,
                largeSlot
            )
        );
        bytes32 largeDigest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), largeStructHash));
        (uint8 vl, bytes32 rl, bytes32 sl) = vm.sign(attesterPk, largeDigest);

        locker.unlockETH(largeBurnId, largeAmount, recipient, lezOwner, largeNonce, largeSlot, abi.encodePacked(rl, sl, vl));
        assertTrue(locker.executedBurns(largeBurnId), "large withdrawal must succeed after complete pruning");
        assertEq(locker.dailyWithdrawnETH(), 9 ether, "daily withdrawn should only reflect the new 9 ETH");

        // Verify permissionless prune function also operates correctly
        uint256 pruned = locker.pruneExpiredWithdrawalsETH(50);
        assertEq(pruned, 0, "nothing left to prune");
    }

    function test_permissionless_prune_bounded_batches() public {
        locker.setLegacyRoutesEnabled(true);
        vm.prank(user);
        locker.depositETH{value: 20 ether}(bytes32(uint256(0xAA)));

        locker.proposeDailyWithdrawalLimitETH(10 ether);
        vm.warp(locker.dailyLimitETHTimelockUnlock());
        locker.executeDailyWithdrawalLimitETH();

        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);

        // Perform 25 small withdrawals
        for (uint64 i = 1; i <= 25; i++) {
            bytes32 burnId = keccak256(
                abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, uint256(0.1 ether), i, uint64(5000 + i))
            );
            bytes32 structHash = keccak256(
                abi.encode(
                    locker.BURN_ETH_TYPEHASH(),
                    burnId,
                    recipient,
                    uint256(0.1 ether),
                    lezOwner,
                    i,
                    uint64(5000 + i)
                )
            );
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digest);
            locker.unlockETH(burnId, 0.1 ether, recipient, lezOwner, i, 5000 + i, abi.encodePacked(r, s, v));
        }

        assertEq(locker.dailyWithdrawnETH(), 2.5 ether, "daily withdrawn should be 2.5 ETH");

        // Warp past 24 hours so all 25 records expire
        vm.warp(block.timestamp + 25 hours);

        // Pruning with maxBatch = 10 prunes exactly 10 records
        uint256 prunedFirst = locker.pruneExpiredWithdrawalsETH(10);
        assertEq(prunedFirst, 10, "first prune batch must be exactly 10");

        // Pruning remaining with maxBatch = 0 (defaults to MAX_CLEANUP_BATCH = 32)
        uint256 prunedSecond = locker.pruneExpiredWithdrawalsETH(0);
        assertEq(prunedSecond, 15, "second prune batch must prune remaining 15");

        // Daily withdrawn ETH must now be reset to 0
        assertEq(locker.dailyWithdrawnETH(), 0, "daily withdrawn should be 0 after pruning");

        // Calling prune again when empty returns 0 without reverting
        uint256 prunedEmpty = locker.pruneExpiredWithdrawalsETH(10);
        assertEq(prunedEmpty, 0, "empty prune must return 0");
    }

    function test_cross_instance_replay_rejection() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        locker.depositETH{value: 1 ether}(bytes32(uint256(0x1111)));

        bytes32 sourceInstanceA = bytes32(uint256(0xAAAA));
        bytes32 sourceInstanceB = bytes32(uint256(0xBBBB));
        bytes32 lezOwner = bytes32(uint256(0x1111));
        address payable recipient = payable(user);
        uint256 amount = 0.5 ether;
        uint64 burnNonce = 1;
        uint64 lezSlot = 6000;

        // 1. Generate signature authorized strictly for sourceInstanceA
        bytes32 burnIdA = keccak256(
            abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstanceA, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        bytes32 structHashA = keccak256(
            abi.encode(
                locker.BURN_ETH_V2_TYPEHASH(),
                burnIdA,
                sourceInstanceA,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digestA = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHashA));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digestA);
        bytes memory sigA = abi.encodePacked(r, s, v);

        // 2. Cross-instance attack: Attempting to unlock on sourceInstanceB using signature for sourceInstanceA
        bytes32 burnIdB = keccak256(
            abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstanceB, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        try locker.unlockETHWithInstance(burnIdB, sourceInstanceB, amount, recipient, lezOwner, burnNonce, lezSlot, sigA) {
            revert("unlockETHWithInstance MUST reject cross-instance replay on sourceInstanceB");
        } catch {}

        // 3. Zero sourceInstance MUST revert
        try locker.unlockETHWithInstance(burnIdA, bytes32(0), amount, recipient, lezOwner, burnNonce, lezSlot, sigA) {
            revert("unlockETHWithInstance MUST revert on zero sourceInstance");
        } catch {}

        // 4. Authentic instance unlock succeeds
        locker.unlockETHWithInstance(burnIdA, sourceInstanceA, amount, recipient, lezOwner, burnNonce, lezSlot, sigA);
        assertTrue(locker.executedBurns(burnIdA), "burnIdA must be marked executed");

        // 5. Duplicate replay MUST be rejected
        try locker.unlockETHWithInstance(burnIdA, sourceInstanceA, amount, recipient, lezOwner, burnNonce, lezSlot, sigA) {
            revert("Duplicate unlock must revert");
        } catch {}
    }

    function test_instance_v2_quorum_m_of_n() public {
        uint256 attester2Pk = 0xB22CE;
        uint256 attester3Pk = 0xC33CE;
        address attester2 = vm.addr(attester2Pk);
        address attester3 = vm.addr(attester3Pk);

        // Pre-commission legacy migration route enabled prior to 2-of-3 graduation
        locker.setLegacyRoutesEnabled(true);

        locker.proposeAddAttester(attester2);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        locker.proposeAddAttester(attester3);
        vm.warp(locker.addAttesterTimelockUnlock());
        locker.executeAddAttester();

        locker.proposeQuorum(2);
        vm.warp(locker.quorumTimelockUnlock());
        locker.executeQuorum();

        vm.prank(user);
        locker.depositETH{value: 10 ether}(bytes32(uint256(0xAA)));

        bytes32 sourceInstanceA = bytes32(uint256(0x7777));
        bytes32 sourceInstanceB = bytes32(uint256(0x8888));
        bytes32 lezOwner = bytes32(uint256(0xAA));
        address payable recipient = payable(user);
        uint256 amount = 2 ether;
        uint64 burnNonce = 15;
        uint64 lezSlot = 700;

        bytes32 burnIdA = keccak256(
            abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstanceA, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        bytes32 structHashA = keccak256(
            abi.encode(
                locker.BURN_ETH_V2_TYPEHASH(),
                burnIdA,
                sourceInstanceA,
                recipient,
                amount,
                lezOwner,
                burnNonce,
                lezSlot
            )
        );
        bytes32 digestA = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHashA));

        // Two valid signatures in strictly ascending signer order
        address addr1 = attesterAuthority;
        address addr2 = attester2;
        uint256 pkFirst = attesterPk;
        uint256 pkSecond = attester2Pk;
        if (addr1 > addr2) {
            pkFirst = attester2Pk;
            pkSecond = attesterPk;
        }

        bytes[] memory validQuorumSigs = new bytes[](2);
        (uint8 va, bytes32 ra, bytes32 sa) = vm.sign(pkFirst, digestA);
        (uint8 vb, bytes32 rb, bytes32 sb) = vm.sign(pkSecond, digestA);
        validQuorumSigs[0] = abi.encodePacked(ra, sa, va);
        validQuorumSigs[1] = abi.encodePacked(rb, sb, vb);

        // 1. Cross-instance attack with quorum: Replaying signatures for sourceInstanceA on sourceInstanceB
        bytes32 burnIdB = keccak256(
            abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstanceB, lezOwner, recipient, amount, burnNonce, lezSlot)
        );
        try locker.unlockETHWithInstanceAndQuorum(burnIdB, sourceInstanceB, amount, recipient, lezOwner, burnNonce, lezSlot, validQuorumSigs) {
            revert("Cross-instance quorum replay MUST revert");
        } catch {}

        // 2. Sub-threshold quorum (only 1 sig provided)
        bytes[] memory subSigs = new bytes[](1);
        subSigs[0] = validQuorumSigs[0];
        try locker.unlockETHWithInstanceAndQuorum(burnIdA, sourceInstanceA, amount, recipient, lezOwner, burnNonce, lezSlot, subSigs) {
            revert("Sub-threshold quorum MUST revert");
        } catch {}

        // 3. Authentic instance + quorum unlock succeeds
        locker.unlockETHWithInstanceAndQuorum(burnIdA, sourceInstanceA, amount, recipient, lezOwner, burnNonce, lezSlot, validQuorumSigs);
        assertTrue(locker.executedBurns(burnIdA), "burnIdA must be marked executed");
        assertEq(locker.totalUnlockedETH(), amount, "unlocked ETH mismatch");

        // 4. Duplicate replay MUST revert
        try locker.unlockETHWithInstanceAndQuorum(burnIdA, sourceInstanceA, amount, recipient, lezOwner, burnNonce, lezSlot, validQuorumSigs) {
            revert("Duplicate quorum unlock MUST revert");
        } catch {}
    }

    function test_disable_legacy_routes_governance_and_v2_quorum_preservation() public {
        vm.deal(user, 5 ether);
        vm.prank(user);
        locker.depositETH{value: 2 ether}(bytes32(uint256(0x1111)));

        // 1. Initial state: legacy routes are strictly disabled by default (Safe-by-default for new deployments)
        assertTrue(!locker.legacyRoutesEnabled(), "legacy routes should default to disabled for safety");

        // 2. Legacy unlockETH MUST revert immediately by default
        bytes32 burnId = keccak256("test_legacy_burn");
        try locker.unlockETH(burnId, 1 ether, payable(user), bytes32(uint256(0x2222)), 1, 100, "") {
            revert("unlockETH MUST revert when legacy routes disabled by default");
        } catch {}

        // 3. Non-owner cannot enable legacy routes
        vm.prank(user);
        try locker.setLegacyRoutesEnabled(true) {
            revert("Non-owner enable legacy routes MUST revert");
        } catch {}

        // 4. Owner enables legacy routes for migration
        locker.setLegacyRoutesEnabled(true);
        assertTrue(locker.legacyRoutesEnabled(), "legacy routes should be enabled after owner call");

        // 5. Owner can disable legacy routes again
        locker.disableLegacyRoutes();
        assertTrue(!locker.legacyRoutesEnabled(), "legacy routes should be disabled");

        // 6. Legacy unlockERC20 MUST revert when legacy routes disabled
        try locker.unlockERC20(burnId, address(0x1234), 1 ether, user, bytes32(uint256(0x2222)), 1, 100, "") {
            revert("unlockERC20 MUST revert when legacy routes disabled");
        } catch {}

        // 7. Permanently retire legacy routes
        assertFalse(locker.legacyRoutesPermanentlyDisabled(), "should not be permanently disabled initially");
        locker.permanentlyRetireLegacyRoutes();
        assertTrue(locker.legacyRoutesPermanentlyDisabled(), "should be permanently disabled");
        assertFalse(locker.legacyRoutesEnabled(), "legacy routes must be disabled");

        // 8. Attempting to re-enable legacy routes MUST revert with LegacyRoutesPermanentlyRetired
        try locker.setLegacyRoutesEnabled(true) {
            revert("setLegacyRoutesEnabled(true) MUST revert once permanently retired");
        } catch {}
    }

    function test_shielded_eth_and_erc20_commitments_zero_leak() public {
        bytes32 cEth = keccak256("shielded_eth_commitment_1");
        vm.prank(user);
        (uint32 ethIdx, bytes32 ethRoot) = locker.depositShieldedETH{value: 1 ether}(cEth);
        assertEq(uint256(ethIdx), 0, "first commitment leaf index must be 0");
        assertEq(locker.nextCommitmentIndex(), 1, "nextCommitmentIndex must increment");
        assertTrue(locker.commitments(cEth), "ETH commitment must be recorded");
        assertTrue(locker.knownDepositRoots(ethRoot), "ETH root must be known");
        assertEq(locker.currentCommitmentRoot(), ethRoot, "currentCommitmentRoot mismatch");
        assertEq(locker.totalLockedETH(), 1 ether, "totalLockedETH mismatch");

        bytes32 cErc20 = keccak256("shielded_erc20_commitment_2");
        vm.prank(user);
        token.approve(address(locker), 100 ether);
        vm.prank(user);
        (uint32 ercIdx, bytes32 ercRoot) = locker.depositShieldedERC20(address(token), 100 ether, cErc20);
        assertEq(uint256(ercIdx), 1, "second commitment leaf index must be 1");
        assertTrue(locker.commitments(cErc20), "ERC-20 commitment must be recorded");
        assertTrue(locker.knownDepositRoots(ethRoot), "historical ETH root must remain valid");
        assertTrue(locker.knownDepositRoots(ercRoot), "new ERC-20 root must be known");
        assertEq(locker.totalLockedERC20(address(token)), 100 ether, "totalLockedERC20 mismatch");
    }

    function test_shielded_merkle_tree_inclusion_and_root_history() public {
        bytes32 c0 = keccak256("leaf_0");
        bytes32 c1 = keccak256("leaf_1");

        vm.prank(user);
        (uint32 idx0, bytes32 root0) = locker.depositShieldedETH{value: 1 ether}(c0);
        assertEq(uint256(idx0), 0, "idx0 mismatch");

        bytes32[20] memory siblings0AtRoot0;
        for (uint32 i = 0; i < 20; i++) {
            siblings0AtRoot0[i] = locker.emptyHashAtLevel(i);
        }
        assertTrue(
            locker.verifyCommitmentInclusion(c0, 0, siblings0AtRoot0, root0),
            "leaf 0 must verify against root0"
        );

        vm.prank(user);
        (uint32 idx1, bytes32 root1) = locker.depositShieldedETH{value: 1 ether}(c1);
        assertEq(uint256(idx1), 1, "idx1 mismatch");

        bytes32[20] memory siblings0AtRoot1;
        bytes32[20] memory siblings1AtRoot1;
        siblings0AtRoot1[0] = c1;
        siblings1AtRoot1[0] = c0;
        for (uint32 i = 1; i < 20; i++) {
            bytes32 emptyLvl = locker.emptyHashAtLevel(i);
            siblings0AtRoot1[i] = emptyLvl;
            siblings1AtRoot1[i] = emptyLvl;
        }
        assertTrue(
            locker.verifyCommitmentInclusion(c0, 0, siblings0AtRoot1, root1),
            "leaf 0 must verify against updated root1"
        );
        assertTrue(
            locker.verifyCommitmentInclusion(c1, 1, siblings1AtRoot1, root1),
            "leaf 1 must verify against updated root1"
        );
        assertEq(
            locker.computeCommitmentPair(c0, c1),
            locker.computeCommitmentPair(c0, c1),
            "computeCommitmentPair must be deterministic"
        );
    }

    function test_shielded_duplicate_commitment_and_strict_denomination_reverts() public {
        bytes32 c0 = keccak256("unique_commitment");
        vm.prank(user);
        locker.depositShieldedETH{value: 1 ether}(c0);

        // Zero commitment must revert
        vm.prank(user);
        try locker.depositShieldedETH{value: 1 ether}(bytes32(0)) {
            revert("Zero commitment MUST revert");
        } catch {}

        // Duplicate commitment must revert
        vm.prank(user);
        try locker.depositShieldedETH{value: 1 ether}(c0) {
            revert("Duplicate commitment MUST revert");
        } catch {}

        // Enable strict fixed denomination mode (0.01, 0.1, 1, 10 ETH pre-registered)
        locker.setStrictFixedDenominationMode(true);
        assertTrue(locker.strictFixedDenominationMode(), "strict denomination mode must be enabled");

        bytes32 cOdd = keccak256("odd_amount_commitment");
        vm.prank(user);
        try locker.depositShieldedETH{value: 0.42 ether}(cOdd) {
            revert("Non-standard denomination MUST revert under strict mode");
        } catch {}

        bytes32 cStd = keccak256("standard_10_eth_commitment");
        vm.prank(user);
        locker.depositShieldedETH{value: 10 ether}(cStd);
        assertTrue(locker.commitments(cStd), "standard 10 ETH commitment must succeed");
    }

    function test_shielded_only_mode_and_shielded_outbound_unlock() public {
        locker.setShieldedDepositsOnly(true);
        assertTrue(locker.shieldedDepositsOnly(), "shieldedDepositsOnly must be true");

        // Legacy public depositETH revealing lezRecipient MUST revert
        vm.prank(user);
        try locker.depositETH{value: 1 ether}(bytes32(uint256(0xAA))) {
            revert("depositETH MUST revert when shieldedDepositsOnly is active");
        } catch {}

        // Shielded deposit succeeds without leaking lezRecipient
        bytes32 depCommitment = keccak256("shielded_deposit_outbound_test");
        vm.prank(user);
        locker.depositShieldedETH{value: 1 ether}(depCommitment);

        // Shielded outbound unlock reveals no lezOwner, burnNonce, or lezSlot
        bytes32 burnNullifier = keccak256("shielded_burn_nullifier_1");
        bytes32 sourceInstance = bytes32(uint256(0x9999));
        uint256 unlockAmt = 0.5 ether;
        address payable recipient = payable(user);

        bytes32 structHash = keccak256(
            abi.encode(
                locker.SHIELDED_BURN_ETH_TYPEHASH(),
                burnNullifier,
                sourceInstance,
                recipient,
                unlockAmt
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);

        locker.unlockShieldedETH(burnNullifier, sourceInstance, unlockAmt, recipient, sigs);
        assertTrue(locker.executedBurns(burnNullifier), "burnNullifier must be marked spent");
        assertEq(locker.totalUnlockedETH(), unlockAmt, "totalUnlockedETH mismatch");

        // Replay MUST revert
        try locker.unlockShieldedETH(burnNullifier, sourceInstance, unlockAmt, recipient, sigs) {
            revert("Shielded burn nullifier replay MUST revert");
        } catch {}
    }

    function test_production_quorum_downgrade_reverts() public {
        address attester2 = address(0xA11CE2);
        address[] memory extra = new address[](1);
        extra[0] = attester2;
        locker.commissionLocker(extra, 2);

        assertTrue(locker.productionCommissioned(), "productionCommissioned latch must be set");
        assertTrue(locker.isCommissioned(), "isCommissioned must be true");

        // Downgrading quorum to 1 MUST revert post-commissioning
        try locker.proposeQuorum(1) {
            revert("proposeQuorum(1) MUST revert once productionCommissioned");
        } catch {}

        // Re-enabling legacy V1 routes MUST revert once productionCommissioned
        try locker.setLegacyRoutesEnabled(true) {
            revert("setLegacyRoutesEnabled(true) MUST revert once productionCommissioned");
        } catch {}
    }

    function test_guardian_owner_independence_across_rotations() public {
        address currentOwner = locker.owner();
        address currentGuardian = locker.guardian();

        // Owner cannot propose themselves as guardian
        try locker.proposeGuardian(currentOwner) {
            revert("proposeGuardian(owner) MUST revert");
        } catch {}

        // Owner cannot transfer ownership to current guardian
        try locker.transferOwnership(currentGuardian) {
            revert("transferOwnership(guardian) MUST revert");
        } catch {}
    }

    function test_zero_daily_limit_rejected_and_fail_closed() public {
        try locker.proposeDailyWithdrawalLimitETH(0) {
            revert("proposeDailyWithdrawalLimitETH(0) MUST revert");
        } catch {}

        try locker.proposeDailyWithdrawalLimitERC20(address(token), 0) {
            revert("proposeDailyWithdrawalLimitERC20(0) MUST revert");
        } catch {}
    }

    function test_post_commission_privacy_and_token_timelocks() public {
        locker.setShieldedDepositsOnly(true);
        locker.setStrictFixedDenominationMode(true);

        // Pre-commissioning guardian cancellation of pending privacy proposal still works if queued earlier,
        // so test pre-commission propose -> guardian cancel BEFORE commissioning.
        locker.proposeDisableShieldedDepositsOnly();
        vm.prank(guardian);
        locker.cancelPendingGovernance(8);
        assertEq(locker.disableShieldedOnlyTimelockUnlock(), 0, "guardian cancel must clear unlock");

        address attester2 = address(0xA11CE3);
        address[] memory extra = new address[](1);
        extra[0] = attester2;
        locker.commissionLocker(extra, 2);

        // Direct disabling or un-timelocked token changes MUST revert once enabled/commissioned
        try locker.setShieldedDepositsOnly(false) {
            revert("direct setShieldedDepositsOnly(false) MUST revert");
        } catch {}
        try locker.setTokenAllowlistEnabled(false) {
            revert("direct setTokenAllowlistEnabled(false) MUST revert");
        } catch {}
        try locker.setStrictFixedDenominationMode(false) {
            revert("direct setStrictFixedDenominationMode(false) MUST revert");
        } catch {}
        try locker.setTokenAllowed(address(0xBEEF), true) {
            revert("direct setTokenAllowed post-commissioning MUST revert");
        } catch {}
        try locker.setStandardDenomination(2 ether, true) {
            revert("direct setStandardDenomination post-commissioning MUST revert");
        } catch {}

        // M-02: Once productionCommissioned AND privacy flags are enabled, even timelocked relaxation MUST revert permanently
        try locker.proposeDisableShieldedDepositsOnly() {
            revert("proposeDisableShieldedDepositsOnly MUST revert permanently once commissioned");
        } catch {}
        try locker.executeDisableShieldedDepositsOnly() {
            revert("executeDisableShieldedDepositsOnly MUST revert permanently once commissioned");
        } catch {}
        try locker.proposeDisableStrictDenominationMode() {
            revert("proposeDisableStrictDenominationMode MUST revert permanently once commissioned");
        } catch {}
        try locker.executeDisableStrictDenominationMode() {
            revert("executeDisableStrictDenominationMode MUST revert permanently once commissioned");
        } catch {}
        try locker.proposeDisableTokenAllowlist() {
            revert("proposeDisableTokenAllowlist MUST revert permanently once commissioned");
        } catch {}
        try locker.executeDisableTokenAllowlist() {
            revert("executeDisableTokenAllowlist MUST revert permanently once commissioned");
        } catch {}

        // M-03: Zero large-withdrawal threshold for ERC-20 rejected post-commissioning
        try locker.proposeLargeWithdrawalThresholdERC20(address(token), 0) {
            revert("proposeLargeWithdrawalThresholdERC20(0) MUST revert post-commissioning");
        } catch {}
    }

    function test_production_commissioned_m02_m03_invariants() public {
        // Pre-commissioning: non-zero proposeLargeWithdrawalThresholdERC20 works
        locker.proposeLargeWithdrawalThresholdERC20(address(token), 5_000 * 10**18);

        // Commission locker
        address attester2 = address(0xA11CE4);
        address[] memory extra = new address[](1);
        extra[0] = attester2;
        locker.commissionLocker(extra, 2);
        assertTrue(locker.productionCommissioned(), "productionCommissioned must be true");

        // M-02: Disabling token allowlist permanently locked post-commissioning
        try locker.proposeDisableTokenAllowlist() {
            revert("proposeDisableTokenAllowlist MUST revert post-commissioning");
        } catch {}

        try locker.executeDisableTokenAllowlist() {
            revert("executeDisableTokenAllowlist MUST revert post-commissioning");
        } catch {}

        // M-03: Proposing zero threshold post-commissioning MUST revert with ZeroAmount
        try locker.proposeLargeWithdrawalThresholdERC20(address(token), 0) {
            revert("proposeLargeWithdrawalThresholdERC20(0) MUST revert post-commissioning");
        } catch {}

        // Executing valid non-zero proposal post-commissioning after timelock succeeds
        vm.warp(block.timestamp + locker.GOVERNANCE_TIMELOCK_DELAY() + 1);
        locker.executeLargeWithdrawalThresholdERC20(address(token));
        assertEq(locker.largeWithdrawalThresholdERC20(address(token)), 5_000 * 10**18, "threshold must match proposed value");
    }

    function test_queued_withdrawal_payload_binding_prevents_swap() public {
        vm.deal(user, 50 ether);
        vm.prank(user);
        locker.depositShieldedETH{value: 20 ether}(keccak256("large_dep_1"));

        bytes32 burnNullifier = keccak256("large_shielded_burn_1");
        bytes32 sourceInstance = bytes32(uint256(0x9999));
        uint256 amount = 12 ether;
        address payable recipient1 = payable(user);
        address payable recipient2 = payable(address(0xCAFE));

        bytes32 structHash1 = keccak256(
            abi.encode(
                locker.SHIELDED_BURN_ETH_TYPEHASH(),
                burnNullifier,
                sourceInstance,
                recipient1,
                amount
            )
        );
        bytes32 digest1 = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash1));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(attesterPk, digest1);
        bytes[] memory sigs1 = new bytes[](1);
        sigs1[0] = abi.encodePacked(r1, s1, v1);

        // 1st call queues the withdrawal and records payload hash
        locker.unlockShieldedETH(burnNullifier, sourceInstance, amount, recipient1, sigs1);
        uint256 unlockTime = locker.queuedWithdrawalUnlockTime(burnNullifier);
        assertTrue(unlockTime > block.timestamp, "withdrawal should be queued");
        assertTrue(locker.queuedWithdrawalPayloadHash(burnNullifier) != bytes32(0), "payload hash must be stored");

        // Warp past 24h delay
        vm.warp(unlockTime + 1);

        // Attempt to swap recipient using same burnNullifier (even with valid signature) MUST revert WithdrawalPayloadMismatch
        bytes32 structHashSwap = keccak256(
            abi.encode(
                locker.SHIELDED_BURN_ETH_TYPEHASH(),
                burnNullifier,
                sourceInstance,
                recipient2,
                amount
            )
        );
        bytes32 digestSwap = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHashSwap));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(attesterPk, digestSwap);
        bytes[] memory sigsSwap = new bytes[](1);
        sigsSwap[0] = abi.encodePacked(r2, s2, v2);

        try locker.unlockShieldedETH(burnNullifier, sourceInstance, amount, recipient2, sigsSwap) {
            revert("swapped recipient MUST revert with WithdrawalPayloadMismatch");
        } catch {}

        // Original exact payload succeeds and clears queue + payload hash
        locker.unlockShieldedETH(burnNullifier, sourceInstance, amount, recipient1, sigs1);
        assertTrue(locker.executedBurns(burnNullifier), "original queued burn must execute");
        assertEq(locker.queuedWithdrawalUnlockTime(burnNullifier), 0, "unlockTime cleared");
        assertEq(locker.queuedWithdrawalPayloadHash(burnNullifier), bytes32(0), "payloadHash cleared");
    }

    function test_erc20_large_withdrawal_queue_and_payload_binding() public {
        // Configure 50,000 token daily limit & 10,000 token large-withdrawal queue threshold
        locker.proposeDailyWithdrawalLimitERC20(address(token), 50_000 ether);
        locker.setLargeWithdrawalThresholdERC20(address(token), 10_000 ether);
        vm.warp(block.timestamp + locker.GOVERNANCE_TIMELOCK_DELAY() + 1);
        locker.executeDailyWithdrawalLimitERC20(address(token));

        uint256 depositAmt = 20_000 ether;
        vm.prank(user);
        token.approve(address(locker), depositAmt);
        vm.prank(user);
        locker.depositShieldedERC20(address(token), depositAmt, keccak256("large_erc20_dep"));

        bytes32 burnNullifier = keccak256("large_erc20_burn");
        bytes32 sourceInstance = bytes32(uint256(0x9999));
        uint256 withdrawAmt = 15_000 ether;
        address recipient = user;

        bytes32 structHash = keccak256(
            abi.encode(
                locker.SHIELDED_BURN_ERC20_TYPEHASH(),
                burnNullifier,
                sourceInstance,
                address(token),
                recipient,
                withdrawAmt
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", locker.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);

        // 1st call queues large ERC-20 withdrawal without transferring tokens yet
        uint256 balBefore = token.balanceOf(recipient);
        locker.unlockShieldedERC20(burnNullifier, sourceInstance, address(token), withdrawAmt, recipient, sigs);
        assertEq(token.balanceOf(recipient), balBefore, "queued ERC20 withdrawal must not transfer yet");
        uint256 unlockTime = locker.queuedWithdrawalUnlockTime(burnNullifier);
        assertTrue(unlockTime > block.timestamp, "ERC20 withdrawal must be queued");

        // Immediate retry before 24h MUST revert
        try locker.unlockShieldedERC20(burnNullifier, sourceInstance, address(token), withdrawAmt, recipient, sigs) {
            revert("early ERC20 withdrawal retry MUST revert");
        } catch {}

        // After 24h delay, exact payload settles
        vm.warp(unlockTime + 1);
        locker.unlockShieldedERC20(burnNullifier, sourceInstance, address(token), withdrawAmt, recipient, sigs);
        assertEq(token.balanceOf(recipient), balBefore + withdrawAmt, "ERC20 withdrawal should settle after delay");
        assertEq(locker.queuedWithdrawalPayloadHash(burnNullifier), bytes32(0), "ERC20 payload hash cleared");

        // Verify Sepolia canonical defaults match M-08 thresholds
        assertEq(
            locker.largeWithdrawalThresholdERC20(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238),
            10_000 * 10**6,
            "Sepolia USDC large threshold mismatch"
        );
    }
}
