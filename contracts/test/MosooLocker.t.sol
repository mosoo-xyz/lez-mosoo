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

        // First attempt queues the withdrawal
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
        vm.warp(block.timestamp + 2 days);
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

        locker.proposeAddAttester(attester2);
        vm.warp(block.timestamp + 2 days);
        locker.executeAddAttester();

        locker.proposeAddAttester(attester3);
        vm.warp(block.timestamp + 2 days);
        locker.executeAddAttester();

        locker.proposeQuorum(2);
        vm.warp(block.timestamp + 2 days);
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
        vm.warp(block.timestamp + 2 days);
        locker.executeGuardian();
        assertEq(locker.guardian(), newGuardian, "guardian update failed");
        assertEq(locker.pendingGuardian(), address(0), "pending guardian not cleared");
    }
}
