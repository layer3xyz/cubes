// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {DeployCube} from "../script/DeployCube.s.sol";
import {Test, console} from "forge-std/Test.sol";
import {DemoCUBE} from "../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";
import {SigUtils} from "./utils/Signature.t.sol";
import {TestCubeContract} from "./TestCubeContract.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    DeployCube public deployer;
    DemoCUBE public demoCube;
    TestCubeContract public testCubeContract;

    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal ownerPubKey;

    address internal realAccount;
    uint256 internal realPrivateKey;

    // Test Users
    address public constant ADMIN_USER = address(1);
    address public constant ALICE = address(2);
    address public constant BOB = address(3);

    function setUp() public {
        deployer = new DeployCube();
        demoCube = deployer.run();

        vm.startBroadcast();
        testCubeContract = new TestCubeContract();
        vm.stopBroadcast();

        sigUtils = new SigUtils("LAYER3", "1");

        ownerPrivateKey = 0xA11CE;
        ownerPubKey = vm.addr(ownerPrivateKey);

        realPrivateKey = vm.envUint("PRIVATE_KEY");
        realAccount = vm.addr(realPrivateKey);

        // vm.startPrank(ADMIN_USER);

        // cube = new DemoCUBE(NAME, SYMBOL, SIGNATURE_DOMAIN, SIGNING_VERSION);
        // uint256 questId = 1;

        // string memory title = "Sample Quest";
        // string[] memory communities = new string[](1);
        // communities[0] = "Test Community";
        // TestCUBE.Difficulty difficulty = TestCUBE.Difficulty.INTERMEDIATE;
        // TestCUBE.QuestType questType = TestCUBE.QuestType.QUEST;

        // cube.initializeQuest(questId, communities, title, difficulty, questType);
    }

    function test_MockSignature() public {
        TestCubeContract.StepCompletionData[] memory steps = new DemoCUBE.StepCompletionData[](1);
        steps[0] = DemoCUBE.StepCompletionData({
            stepChainId: 137,
            stepTxHash: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002
        });

        TestCubeContract.CubeData memory cubeData = DemoCUBE.CubeData({
            questId: 224040309745014662610336485866037874947,
            userId: 7,
            timestamp: 1700151763,
            nonce: 224040309745014662610336485866037874947,
            walletName: "Metamask",
            steps: steps,
            tokenUri: "ipfs://QmeDofVWQPJfmHNyaF73FzBedPd2dhhCy4JudXguVfaEQL",
            toAddress: 0x925e4b930c2a3597c876277308b9efa5bfa1061C
        });

        bytes32 digest = testCubeContract.getStructHash(cubeData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(realPrivateKey, digest);

        bytes memory signature = new bytes(65);
        signature[0] = bytes1(v);
        for (uint256 i = 0; i < 32; i++) {
            signature[i + 1] = r[i];
            signature[i + 33] = s[i];
        }

        console.logBytes32(bytes32(signature));
        console.logBytes32(digest);

        //testCubeContract.mintCube(cubeData, signature);

        //testCubeContract.getSigner(cubeData, signature)
    }

    // function test_Signature() public {
    //     // uint256 questId;
    //     // uint256 userId;
    //     // uint256 timestamp;
    //     // uint256 nonce;
    //     // string walletProvider;
    //     // string tokenURI;
    //     // // StepCompletionData[] steps;
    //     // address toAddress;

    //     // 1. insert data and get back typed data to be signed (i.e. struct)
    //     SigUtils.CubeData memory cubeData = SigUtils.CubeData({
    //         questId: 224040309745014662610336485866037874947,
    //         userId: 7,
    //         timestamp: 1700151763,
    //         nonce: 224040309745014662610336485866037874947,
    //         walletName: "Metamask",
    //         tokenUri: "ipfs://QmeDofVWQPJfmHNyaF73FzBedPd2dhhCy4JudXguVfaEQL",
    //         toAddress: 0x925e4b930c2a3597c876277308b9efa5bfa1061C
    //     });
    //     // 2. sign data
    //     // 3. mint token

    //     // get hash of the typed data
    //     bytes32 digest = sigUtils.getStructHash(cubeData);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(realPrivateKey, digest);
    //     address signer = ecrecover(digest, v, r, s);
    //     console.log("owner pub key %s and signer %s", realAccount, signer);
    //     console.logBytes32(digest);

    //     bytes memory signature = new bytes(65);
    //     signature[0] = bytes1(v);
    //     for (uint256 i = 0; i < 32; i++) {
    //         signature[i + 1] = r[i];
    //         signature[i + 33] = s[i];
    //     }
    //     console.log("signature %s", toHexString(signature));
    //     //console.log("digest %s", digest);

    //     //(uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

    //     // token.permit(permit.owner, permit.spender, permit.value, permit.deadline, v, r, s);

    //     // assertEq(token.allowance(owner, spender), 1e18);
    //     // assertEq(token.nonces(owner), 1);
    //     assertEq(signer, realAccount);
    // }

    // function getTestCubeInput() public returns (TestCUBE.CubeData calldata) {
    //     TestCUBE.CubeData[] memory cubeInputs = new TestCUBE.CubeData[](1);
    //     TestCUBE.StepCompletionData[] memory steps = new TestCUBE.StepCompletionData[](1);
    //     bytes32 txHashExample = 0x00000000;
    //     steps[0] = TestCUBE.StepCompletionData(0x00000000, 1);
    //     cubeInputs[0] = TestCUBE.CubeData(1, 1, "Test Wallet", steps, "ipfs://asdfasdf", 1000, address(2));

    //     return cubeInputs[0];
    // }

    // generateSignatureForCubeInput is similar to what will be run on our backend to generate the offchain signature
    // function generateSignatureForCubeInput(
    //     TestCUBE.CubeInputData memory cubeInput,
    //     uint256 privateKey
    // ) public returns (bytes memory) {
    //     bytes32 hashedMessage = keccak256(cube._encodeCubeInput(getTestCubeInput()));
    //     bytes32 hashedMessageWithEthPrefix = hashedMessage.toEthSignedMessageHash();

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hashedMessageWithEthPrefix);
    //     bytes memory signature = abi.encodePacked(r, s, v);
    //     return signature;
    // }

    // function test_createsAValidSignature() public {
    //     bytes memory offChainSignatureGeneratedByDeployer =
    //         generateSignatureForCubeInput(getTestCubeInput(), deployerPrivateKey);

    //     address recoveredSigner =
    //         cube._recover(getTestCubeInput(), offChainSignatureGeneratedByDeployer);

    //     assertEq(vm.addr(deployerPrivateKey), recoveredSigner);
    // }

    // function testFail_userSignatureShouldThrow() public {
    //     bytes memory offChainSignatureGeneratedByUser =
    //         generateSignatureForCubeInput(getTestCubeInput(), userPrivateKey);

    //     // will revert with "Signature must be from the owner"
    //     cube.verify(getTestCubeInput(), offChainSignatureGeneratedByUser);
    // }

    // function test_deployerSignatureShouldNotThrow() public {
    //     bytes memory offChainSignatureGeneratedByDeployer =
    //         generateSignatureForCubeInput(getTestCubeInput(), deployerPrivateKey);

    //     cube.verify(getTestCubeInput(), offChainSignatureGeneratedByDeployer);
    // }

    function toHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * data.length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            buffer[2 + i * 2] = char(bytes1(uint8(data[i] >> 4)));
            buffer[3 + i * 2] = char(bytes1(uint8(data[i] & 0x0f)));
        }
        return string(buffer);
    }

    function char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }
}
