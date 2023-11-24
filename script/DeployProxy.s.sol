// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {CubeV1} from "../src/CubeV1.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployProxy is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;

    string public constant NAME = "DemoCUBE";
    string constant SYMBOL = "TCUBE";
    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    function run(address _admin) external returns (address) {
        if (block.chainid == 31337) {
            deployerKey = DEFAULT_ANVIL_PRIVATE_KEY;
        } else {
            deployerKey = vm.envUint("PRIVATE_KEY");
        }

        address proxy = deployProxy(_admin);

        return proxy;
    }

    function deployProxy(address _admin) public returns (address) {
        vm.startPrank(_admin);
        CubeV1 cube = new CubeV1();
        ERC1967Proxy proxy = new ERC1967Proxy(address(cube), "");
        CubeV1(payable(proxy)).initialize(NAME, SYMBOL, SIGNATURE_DOMAIN, SIGNING_VERSION);
        vm.stopPrank();
        return address(proxy);
    }
}
