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

        address proxyAddr = 0x1195Cf65f83B3A5768F3C496D3A05AD6412c64B7;
        address upgrader = 0xbA90242A8812c3e340B273873189F40B4A3B6DA1;
        upgradeCube(upgrader, proxyAddr);
    }

    function upgradeCube(address _upgrader, address _proxyAddress) public {
        console.log("upgrader ", _upgrader);
        vm.startBroadcast(_upgrader);

        Upgrades.upgradeProxy(_proxyAddress, "CUBE.sol", new bytes(0));
        vm.stopBroadcast();
    }
}
