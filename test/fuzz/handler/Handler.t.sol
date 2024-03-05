// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, StdInvariant, stdError} from "forge-std/Test.sol";
import {Escrow} from "../../../src/escrow/Escrow.sol";
import {MockERC20} from "../../mock/MockERC20.sol";

contract Handler is Test {
    MockERC20 public erc20Mock;
    Escrow public escrow;

    address public admin;
    address public treasury;
    address public alice = makeAddr("alice");

    constructor(Escrow _escrow, MockERC20 _erc20Mock, address _admin, address _treasury) {
        escrow = _escrow;
        erc20Mock = _erc20Mock;

        admin = _admin;
        treasury = _treasury;
    }

    function depositERC20(uint256 amount) public {
        amount = erc20Mock.balanceOf(admin);
        vm.startPrank(admin);
        erc20Mock.transfer(address(escrow), amount);
    }

    function withdrawERC20(uint256 amount, uint256 rakeBps) public {
        amount = bound(amount, 0, erc20Mock.balanceOf(address(escrow)));
        rakeBps = bound(rakeBps, 0, 10_000);
        vm.startPrank(admin);
        escrow.withdrawERC20(address(erc20Mock), alice, amount, rakeBps);
        vm.stopPrank();
    }
}
