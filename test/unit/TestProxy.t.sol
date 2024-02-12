// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {UpgradeCube} from "../../script/UpgradeCube.s.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CubeV2} from "../contracts/CubeV2.sol";
import {CUBE} from "../../src/CUBE.sol";

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

        // setup necessary roles
        vm.startBroadcast(OWNER);
        CUBE(payable(proxyAddress)).grantRole(keccak256("UPGRADER"), OWNER);
        vm.stopBroadcast();
    }

    function testERC721Name() public {
        upgradeCube.upgradeCube(OWNER, proxyAddress);

        string memory expectedValue = deployProxy.NAME();
        assertEq(expectedValue, CubeV2(payable(proxyAddress)).name());
    }

    function testUnauthorizedUpgrade() public {
        bytes4 selector = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, BOB, keccak256("UPGRADER"));
        vm.expectRevert(expectedError);
        upgradeCube.upgradeCube(BOB, proxyAddress);
    }

    function testV2SignerRoleVariable() public {
        upgradeCube.upgradeCube(OWNER, proxyAddress);

        CubeV2 newCube = CubeV2(payable(proxyAddress));
        bytes32 signerRole = newCube.SIGNER_ROLE();
        assertEq(keccak256("SIGNER"), signerRole);
    }

    function testV2MigratedName() public {
        upgradeCube.upgradeCube(OWNER, proxyAddress);

        CubeV2 newCube = CubeV2(payable(proxyAddress));

        string memory val = newCube.name();
        assertEq(val, "Layer3 CUBE");
    }
}
