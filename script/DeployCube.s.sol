// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {DemoCube2} from "../src/CUBE.sol";

contract DeployCube is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;

    string constant NAME = "DemoCUBE";
    string constant SYMBOL = "TCUBE";
    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    function run() external returns (DemoCube2) {
        if (block.chainid == 31337) {
            deployerKey = DEFAULT_ANVIL_PRIVATE_KEY;
        } else {
            deployerKey = vm.envUint("PRIVATE_KEY");
        }

        DemoCube2 cube = new DemoCube2(
            NAME, SYMBOL, SIGNATURE_DOMAIN, SIGNING_VERSION
        );
        return cube;
    }
}
