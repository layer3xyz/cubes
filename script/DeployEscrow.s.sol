// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";

import {Factory} from "../src/escrow/Factory.sol";
import {IFactory} from "../src/escrow/interfaces/IFactory.sol";
import {MockERC20} from "../test/mock/MockERC20.sol";
import {MockERC721} from "../test/mock/MockERC721.sol";
import {MockERC1155} from "../test/mock/MockERC1155.sol";

import {CUBE} from "../src/CUBE.sol";

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DeployEscrow is Script {
    // private key is the same for everyone
    uint256 public DEFAULT_ANVIL_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public deployerKey;

    uint256 public constant QUEST_ID = 1;

    Factory public factoryContract;
    address erc20Mock;
    address erc721Mock;
    address erc1155Mock;

    function run(address admin, address treasury, address cube)
        external
        returns (address, address, address, address, address)
    {
        // deploy nft contract and set factory address
        deployTokenContracts(admin);

        address factory = deployFactory(admin, cube);
        factoryContract = Factory(factory);

        address[] memory whitelistedTokens = new address[](3);
        whitelistedTokens[0] = erc20Mock;
        whitelistedTokens[1] = erc721Mock;
        whitelistedTokens[2] = erc1155Mock;
        address escrow = deployEscrow(admin, QUEST_ID, whitelistedTokens, treasury);

        return (factory, escrow, erc20Mock, erc721Mock, erc1155Mock);
    }

    function deployTokenContracts(address admin) public {
        address erc20 = deployERC20Mock(admin);
        address erc721 = deployERC721Mock(admin);
        address erc1155 = deployERC1155Mock(admin);

        erc20Mock = erc20;
        erc721Mock = erc721;
        erc1155Mock = erc1155;
    }

    function deployFactory(address _admin, address cube) public returns (address) {
        vm.startBroadcast(_admin);
        Options memory opts;
        opts.constructorData = abi.encode(CUBE(cube));
        address proxy = Upgrades.deployUUPSProxy(
            "Factory.sol", abi.encodeCall(Factory.initialize, (_admin)), opts
        );

        vm.stopBroadcast();
        return proxy;
    }

    function deployEscrow(
        address _admin,
        uint256 questId,
        address[] memory tokens,
        address treasury
    ) public returns (address) {
        vm.startBroadcast(_admin);
        factoryContract.createEscrow(questId, _admin, tokens, treasury);

        // get the escrow's address
        address escrow = factoryContract.s_escrows(questId);
        vm.stopBroadcast();
        return escrow;
    }

    function depositToFactory(address depositor, uint256 amount) public {
        vm.startBroadcast(depositor);
        address escrowAddr = factoryContract.s_escrows(QUEST_ID);
        IERC20(erc20Mock).transfer(escrowAddr, amount);
        vm.stopBroadcast();
    }

    function deployERC20Mock(address _admin) public returns (address) {
        vm.startBroadcast(_admin);
        MockERC20 erc20 = new MockERC20();
        erc20.mint(_admin, 20e18);
        vm.stopBroadcast();
        return address(erc20);
    }

    function deployERC721Mock(address _admin) public returns (address) {
        vm.startBroadcast(_admin);
        MockERC721 erc721 = new MockERC721();

        erc721.mint(_admin);
        erc721.mint(_admin);
        erc721.mint(_admin);

        vm.stopBroadcast();
        return address(erc721);
    }

    function deployERC1155Mock(address _admin) public returns (address) {
        vm.startBroadcast(_admin);
        MockERC1155 erc1155 = new MockERC1155();
        erc1155.mint(_admin, 100, 0);

        vm.stopBroadcast();
        return address(erc1155);
    }
}
