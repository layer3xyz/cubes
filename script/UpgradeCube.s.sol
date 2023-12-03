// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {CubeV1} from "../src/CubeV1.sol";
import {CubeV2} from "../src/CubeV2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract UpgradeCube is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;
    address public OWNER = address(0);

    function run(address _proxyAddress) external returns (address) {
        address proxy = upgradeCube(OWNER, _proxyAddress, 55);
        return proxy;
    }

    function upgradeCube(address _admin, address _proxyAddress, uint256 _newVal)
        public
        returns (address)
    {
        vm.startPrank(_admin);
        CubeV1 proxy = CubeV1(payable(_proxyAddress));

        Upgrades.upgradeProxy(
            _proxyAddress, "CubeV2.sol", abi.encodeCall(CubeV2.initializeV2, _newVal)
        );
        vm.stopPrank();
        return address(proxy);
    }
}
