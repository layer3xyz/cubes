// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

// Invariants:
// - only a minter can issue a valid mint voucher
// - not possible to mint if the minting is turned off
// - only withdrawer/admin can withdraw from contract

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Handler} from "./Handler.t.sol";
import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {CUBE} from "../../src/CUBE.sol";

contract Invariant is StdInvariant, Test {
    CUBE cube;
    uint256 internal adminPrivateKey;
    address internal adminAddress;
    DeployProxy deployer;
    address proxyAddress;

    function setUp() public {
        adminPrivateKey = 0x01;
        adminAddress = vm.addr(adminPrivateKey);

        deployer = new DeployProxy();
        proxyAddress = deployer.deployProxy(adminAddress);
        cube = CUBE(payable(proxyAddress));
        targetContract(address(cube));
    }

    // NOTE: WIP
    // function invariantOnlyMintIfActive() public {}
    // function invariantOnlyMintIfSignedByMinter() public {}
    // function invariantOnlyWithdrawIfAdmin() public {}
}
