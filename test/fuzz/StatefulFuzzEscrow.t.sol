// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, StdInvariant, stdError} from "forge-std/Test.sol";
import {Escrow} from "../../src/escrow/Escrow.sol";
import {MockERC20} from "../mock/MockERC20.sol";

contract StatefulFuzzEscrow is StdInvariant, Test {
    Escrow public escrow;
    MockERC20 public erc20Mock;

    address public s_admin = makeAddr("admin");
    address public s_treasury = makeAddr("treasury");
    address public s_alice = makeAddr("alice");

    address[] public s_whitelistedTokens;

    function setUp() public {
        vm.startPrank(s_admin);

        erc20Mock = new MockERC20();
        s_whitelistedTokens.push(address(erc20Mock));

        escrow = new Escrow(s_whitelistedTokens, s_treasury);
        targetContract(address(escrow));
        vm.stopPrank();
    }
}
