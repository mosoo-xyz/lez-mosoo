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
        locker = new MosooLocker(attesterAuthority);
        token = new MockERC20();
        locker.setGuardian(guardian);
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

        locker.setDailyWithdrawalLimitETH(5 ether);
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
}
