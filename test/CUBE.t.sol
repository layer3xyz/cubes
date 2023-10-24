// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {TestCUBE} from "../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";
import {console} from "forge-std/console.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    TestCUBE public cube;

    uint256 internal userPrivateKey;
    uint256 internal deployerPrivateKey;

    struct Community {
        uint16 communityId;
        string communityName;
    }

    function setUp() public {
        deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        (address alice, uint256 alicePk) = makeAddrAndKey("alice testgirl");
        userPrivateKey = alicePk;

        console.log(vm.addr(deployerPrivateKey));
        vm.startPrank(vm.addr(deployerPrivateKey));

        cube = new TestCUBE();
        uint256 questId = 1;

        string memory title = "Sample Quest";
        TestCUBE.Community[] memory communities = new TestCUBE.Community[](1);
        communities[0] = TestCUBE.Community(1, "Test Community");
        uint8 difficulty = 1;
        TestCUBE.QuestType questType = TestCUBE.QuestType.QUEST;

        cube.initializeQuest(questId, communities, title, difficulty, questType);

        vm.stopPrank();
    }

    function getTestCubeInput() public returns (TestCUBE.CubeInputData memory) {
        TestCUBE.CubeInputData[] memory cubeInputs = new TestCUBE.CubeInputData[](1);
        TestCUBE.StepCompletionData[] memory steps = new TestCUBE.StepCompletionData[](1);
        bytes32 txHashExample = 0x00000000;
        steps[0] = TestCUBE.StepCompletionData(0x00000000, 1);
        cubeInputs[0] = TestCUBE.CubeInputData(1, 1, "Test Wallet", steps);

        return cubeInputs[0];
    }

    // generateSignatureForCubeInput is similar to what will be run on our backend to generate the offchain signature
    function generateSignatureForCubeInput(
        TestCUBE.CubeInputData memory cubeInput,
        uint256 privateKey
    ) public returns (bytes memory) {
        bytes32 hashedMessage = keccak256(cube._encodeCubeInput(getTestCubeInput()));
        bytes32 hashedMessageWithEthPrefix = hashedMessage.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hashedMessageWithEthPrefix);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function test_createsAValidSignature() public {
        bytes memory offChainSignatureGeneratedByDeployer =
            generateSignatureForCubeInput(getTestCubeInput(), deployerPrivateKey);

        address recoveredSigner =
            cube._recover(getTestCubeInput(), offChainSignatureGeneratedByDeployer);

        assertEq(vm.addr(deployerPrivateKey), recoveredSigner);
    }

    function testFail_userSignatureShouldThrow() public {
        bytes memory offChainSignatureGeneratedByUser =
            generateSignatureForCubeInput(getTestCubeInput(), userPrivateKey);

        // will revert with "Signature must be from the owner"
        cube.verify(getTestCubeInput(), offChainSignatureGeneratedByUser);
    }

    function test_deployerSignatureShouldNotThrow() public {
        bytes memory offChainSignatureGeneratedByDeployer =
            generateSignatureForCubeInput(getTestCubeInput(), deployerPrivateKey);

        cube.verify(getTestCubeInput(), offChainSignatureGeneratedByDeployer);
    }
}
