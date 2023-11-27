// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {DeployProxy} from "../script/DeployProxy.s.sol";
import {UpgradeCube} from "../script/UpgradeCube.s.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CubeV1} from "../src/CubeV1.sol";
import {CubeV2} from "../src/CubeV2.sol";

contract DeployAndUpgradeTest is StdCheats, Test {
    DeployProxy public deployProxy;
    UpgradeCube public upgradeCube;
    address public OWNER = address(1);

    // this address should always remain the same
    address public proxyAddress;

    function setUp() public {
        deployProxy = new DeployProxy();
        upgradeCube = new UpgradeCube();
        proxyAddress = deployProxy.deployProxy(OWNER);
    }

    function testERC721Name() public {
        CubeV2 cube2 = new CubeV2();

        upgradeCube.upgradeCube(OWNER, proxyAddress, address(cube2), new bytes(0));

        string memory expectedValue = deployProxy.NAME();
        assertEq(expectedValue, CubeV2(payable(proxyAddress)).name());
    }

    function testV2SignerRoleVariable() public {
        CubeV2 cube2 = new CubeV2();

        upgradeCube.upgradeCube(OWNER, proxyAddress, address(cube2), new bytes(0));

        CubeV2 newCube = CubeV2(payable(proxyAddress));
        bytes32 signerRole = newCube.SIGNER_ROLE();
        assertEq(keccak256("SIGNER_ROLE"), signerRole);
    }

    function testV2MigratedVariable() public {
        CubeV2 cube2 = new CubeV2();

        uint256 newVal = 12345;
        bytes memory data = abi.encodeWithSignature("migrateV2(uint256)", newVal);

        upgradeCube.upgradeCube(OWNER, proxyAddress, address(cube2), data);

        CubeV2 newCube = CubeV2(payable(proxyAddress));

        uint256 val = newCube.newValueV2();
        assertEq(val, newVal);
    }
}
