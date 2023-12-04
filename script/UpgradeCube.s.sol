// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {CUBE} from "../src/CUBE.sol";
import {CubeV2} from "../src/CubeV2.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract UpgradeCube is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;
    address public OWNER = address(0);

    function upgradeCube(address _admin, address _proxyAddress, uint256 _newVal)
        public
        returns (address)
    {
        vm.startPrank(_admin);
        CUBE proxy = CUBE(payable(_proxyAddress));

        Upgrades.upgradeProxy(
            _proxyAddress, "CubeV2.sol", abi.encodeCall(CubeV2.initializeV2, _newVal)
        );
        vm.stopPrank();
        return address(proxy);
    }
}
