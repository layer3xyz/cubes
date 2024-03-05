// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, StdInvariant, stdError} from "forge-std/Test.sol";
import {Escrow} from "../../../src/escrow/Escrow.sol";
import {MockERC20} from "../../mock/MockERC20.sol";
import {Handler} from "./Handler.t.sol";

contract Invariant is StdInvariant, Test {
    Handler handler;

    Escrow public escrow;
    MockERC20 public erc20Mock;

    address public admin = makeAddr("admin");
    address public treasury = makeAddr("treasury");
    address public alice = makeAddr("alice");

    address[] public whitelistedTokens;

    uint256 public startingAmount = 10e18;

    function setUp() public {
        vm.startPrank(admin);

        erc20Mock = new MockERC20();
        erc20Mock.mint(admin, startingAmount);
        whitelistedTokens.push(address(erc20Mock));

        escrow = new Escrow(admin, whitelistedTokens, treasury);

        // deposit to escrow
        erc20Mock.transfer(address(escrow), startingAmount);

        handler = new Handler(escrow, erc20Mock, admin, treasury);

        vm.stopPrank();

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = handler.depositERC20.selector;
        selectors[1] = handler.withdrawERC20.selector;

        FuzzSelector memory fs = FuzzSelector(address(handler), selectors);
        targetSelector(fs);

        targetContract(address(handler));
    }

    function statefulFuzz_testInvariantBreakHandler() public {
        uint256 amount = 1e18;
        uint256 bps = 300;

        uint256 preBalAlice = erc20Mock.balanceOf(alice);
        uint256 preBalTreasury = erc20Mock.balanceOf(treasury);

        vm.startPrank(admin);

        try escrow.withdrawERC20(address(erc20Mock), alice, amount, bps) {
            uint256 rake = amount * bps / 10_000;

            assert(erc20Mock.balanceOf(alice) == preBalAlice + (amount - rake));
            assert(erc20Mock.balanceOf(treasury) == preBalTreasury + rake);
        } catch {
            assert(erc20Mock.balanceOf(alice) == preBalAlice);
        }
        vm.stopPrank();

        // assert(erc20Mock.balanceOf(address(escrow)) == 0);
        // assert(yeildERC20.balanceOf(address(handlerStatefulFuzzCatches)) == 0);
        // assert(mockUSDC.balanceOf(owner) == startingAmount);
        // assert(yeildERC20.balanceOf(owner) == startingAmount);
    }

    function statefulFuzz_testRakeCalculationAndTransfer() public {
        uint256 amountToWithdraw = 1e18;
        uint256 bps = 300;

        uint256 preBalTreasury = erc20Mock.balanceOf(treasury);

        vm.prank(admin);
        escrow.withdrawERC20(address(erc20Mock), alice, amountToWithdraw, bps);

        uint256 rake = amountToWithdraw * bps / 10_000;
        assert(erc20Mock.balanceOf(treasury) == preBalTreasury + rake);
    }

    function statefulFuzz_testWithdrawalFailsToZeroAddress() public {
        uint256 amountToWithdraw = 1e18;
        uint256 bps = 300;

        vm.prank(admin);
        try escrow.withdrawERC20(address(erc20Mock), address(0), amountToWithdraw, bps) {
            revert("Expected withdrawal to fail due to zero address");
        } catch (bytes memory) {
            // Expected failure, do nothing
        }

        assert(erc20Mock.balanceOf(address(escrow)) == startingAmount);
    }

    function statefulFuzz_testWithdrawalFailsIfAmountExceedsBalance() public {
        uint256 amountToWithdraw = startingAmount + 1e18; // Attempt to withdraw more than the escrow's balance

        vm.prank(admin);
        try escrow.withdrawERC20(address(erc20Mock), alice, amountToWithdraw, 300) {
            revert("Expected withdrawal to fail due to insufficient balance");
        } catch (bytes memory) /*lowLevelData*/ {
            // Expected failure, do nothing
        }

        assert(erc20Mock.balanceOf(address(escrow)) == startingAmount);
    }

    function statefulFuzz_testWithdrawalOnlyForWhitelistedTokens() public {
        // Assuming `erc20Mock` is not whitelisted
        uint256 amountToWithdraw = 1e18;
        address randomToken = makeAddr("token");

        vm.prank(admin);
        try escrow.withdrawERC20(randomToken, alice, amountToWithdraw, 300) {
            revert("Expected withdrawal to fail due to token not being whitelisted");
        } catch (bytes memory) /*lowLevelData*/ {
            // Expected failure, do nothing
        }

        assert(erc20Mock.balanceOf(address(escrow)) == startingAmount);
    }
}
