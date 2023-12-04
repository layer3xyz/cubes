// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {UpgradeCube} from "../../script/UpgradeCube.s.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CubeV2} from "../../src/CubeV2.sol";

contract DeployAndUpgradeTest is StdCheats, Test {
    DeployProxy public deployProxy;
    UpgradeCube public upgradeCube;
    address public OWNER = address(1);
    address public ALICE = address(2);
    address public BOB = address(3);

    // this address should always remain the same
    address public proxyAddress;

    function setUp() public {
        deployProxy = new DeployProxy();
        upgradeCube = new UpgradeCube();
        proxyAddress = deployProxy.deployProxy(OWNER);
    }

    function testERC721Name() public {
        upgradeCube.upgradeCube(OWNER, proxyAddress, 55);

        string memory expectedValue = deployProxy.NAME();
        assertEq(expectedValue, CubeV2(payable(proxyAddress)).name());
    }

    function testV2SignerRoleVariable() public {
        upgradeCube.upgradeCube(OWNER, proxyAddress, 55);

        CubeV2 newCube = CubeV2(payable(proxyAddress));
        bytes32 signerRole = newCube.SIGNER_ROLE();
        assertEq(keccak256("SIGNER"), signerRole);
    }

    function testV2MigratedVariable() public {
        uint256 newVal = 12345;

        upgradeCube.upgradeCube(OWNER, proxyAddress, newVal);

        CubeV2 newCube = CubeV2(payable(proxyAddress));

        uint256 val = newCube.newValueV2();
        assertEq(val, newVal);
    }
}
