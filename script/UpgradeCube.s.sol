// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {CUBE} from "../src/CUBE.sol";
import {CubeV2} from "../test/contracts/CubeV2.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract UpgradeCube is Script {
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;

    function run() public {
        // if (block.chainid == 31337) {
        //     deployerKey = DEFAULT_ANVIL_PRIVATE_KEY;
        // } else {
        //     deployerKey = vm.envUint("PRIVATE_KEY");
        // }

        address proxyAddr = 0xEc9FC487733FcDA6fC62B5CA6C5109e8dB3d3Ce8;
        address admin = 0x225d5BF80f4164eB8F7CE8408dD2Cfb9e35a8C57;
        upgradeCube(admin, proxyAddr);
    }

    function upgradeCube(address _admin, address _proxyAddress) public {
        console.log("admin ", _admin);
        vm.startBroadcast(_admin);

        Upgrades.upgradeProxy(_proxyAddress, "CUBE.sol", new bytes(0));
        vm.stopBroadcast();
    }
}
