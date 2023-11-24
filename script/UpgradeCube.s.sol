// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {CubeV1} from "../src/CubeV1.sol";
import {CubeV2} from "../src/CubeV2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";

contract UpgradeCube is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;
    address public OWNER = address(0);

    function run() external returns (address) {
        address mostRecentlyDeployedProxy =
            DevOpsTools.get_most_recent_deployment("ERC1967Proxy", block.chainid);
        CubeV2 newCube = new CubeV2();
        address proxy =
            upgradeCube(OWNER, mostRecentlyDeployedProxy, address(newCube), new bytes(0));
        return proxy;
    }

    function upgradeCube(
        address _admin,
        address proxyAddress,
        address cubeV2Address,
        bytes memory _upgradeData
    ) public returns (address) {
        vm.startPrank(_admin);
        CubeV1 proxy = CubeV1(payable(proxyAddress));

        proxy.upgradeToAndCall(address(cubeV2Address), _upgradeData); // proxy now gets its logic from this new address `cubeV2Address`
        vm.stopPrank();
        return address(proxy);
    }
}
