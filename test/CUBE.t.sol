// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {DeployCube} from "../script/DeployCube.s.sol";
import {DeployProxy} from "../script/DeployProxy.s.sol";
import {Test, console} from "forge-std/Test.sol";
import {DemoCUBE} from "../src/CUBE.sol";
import {CubeV1} from "../src/CubeV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";
import {SigUtils} from "./utils/Signature.t.sol";
import {TestCubeContract} from "./TestCubeContract.sol";
import {EIP712Upgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    DeployProxy public deployer;
    CubeV1 public demoCube;
    TestCubeContract public testCubeContract;

    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal ownerPubKey;

    address internal realAccount;
    uint256 internal realPrivateKey;

    // Test Users
    address public constant ADMIN_USER = address(1);
    address public constant ALICE = address(2);
    address public constant BOB = address(3);

    address public proxyAddress;

    function setUp() public {
        ownerPrivateKey = 0xA11CE;
        ownerPubKey = vm.addr(ownerPrivateKey);

        deployer = new DeployProxy();
        proxyAddress = deployer.deployProxy(ownerPubKey);
        demoCube = CubeV1(payable(proxyAddress));

        vm.startBroadcast();
        testCubeContract = new TestCubeContract();
        vm.stopBroadcast();

        sigUtils = new SigUtils(SIGNATURE_DOMAIN, SIGNING_VERSION);
    }

    function testSignature() public {
        CubeV1.TransactionData[] memory transactions = new CubeV1.TransactionData[](1);
        transactions[0] = CubeV1.TransactionData({
            txHash: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002,
            chainId: 137
        });

        CubeV1.CubeData memory cubeData = CubeV1.CubeData({
            questId: 224040309745014662610336485866037874947,
            userId: 7,
            completedAt: 1700151763,
            nonce: 224040309745014662610336485866037874947,
            price: 7777777777777777,
            walletProvider: "MetaMask",
            tokenURI: "ipfs://QmeDofVWQPJfmHNyaF73FzBedPd2dhhCy4JudXguVfaEQL",
            embedOrigin: "woofi.org",
            toAddress: 0x925e4b930c2a3597c876277308b9efa5bfa1061C,
            transactions: transactions
        });

        bytes32 digest = testCubeContract.getStructHash(cubeData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);

        address signerAddr = sigUtils.recoverSigner(digest, signature);
        console.log("signer address %s is the same as the supposed %s?", signerAddr, ownerPubKey);
        assertEq(signerAddr, ownerPubKey);
    }
}
