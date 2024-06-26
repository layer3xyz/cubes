// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {CUBE} from "../src/CUBE.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DeployProxy is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;

    string public constant NAME = "Layer3 CUBE";
    string public constant SYMBOL = "CUBE";
    string public constant SIGNATURE_DOMAIN = "LAYER3";
    string public constant SIGNING_VERSION = "1";

    function run() external returns (address) {
        if (block.chainid == 31337) {
            deployerKey = DEFAULT_ANVIL_PRIVATE_KEY;
        } else {
            deployerKey = vm.envUint("PRIVATE_KEY");
        }

        address proxy = deployProxy(vm.addr(deployerKey));

        return proxy;
    }

    function deployProxy(address _admin) public returns (address) {
        vm.startBroadcast(_admin);
        address proxy = Upgrades.deployUUPSProxy(
            "CUBE.sol",
            abi.encodeCall(
                CUBE.initialize, (NAME, SYMBOL, SIGNATURE_DOMAIN, SIGNING_VERSION, _admin)
            )
        );
        vm.stopBroadcast();
        return address(proxy);
    }
}
