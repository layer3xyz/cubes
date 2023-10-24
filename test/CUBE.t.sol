// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {TestCUBE} from "../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;

    TestCUBE public cube;

    struct Community {
        uint16 communityId;
        string communityName;
    }

    function setUp() public {
        cube = new TestCUBE();
        uint256 questId = 1;

        string memory title = "Sample Quest";
        TestCUBE.Community[] memory communities = new TestCUBE.Community[](1);
        communities[0] = TestCUBE.Community(1, "Test Community");
        uint8 difficulty = 1;
        TestCUBE.QuestType questType = TestCUBE.QuestType.QUEST;

        cube.initializeQuest(questId, communities, title, difficulty, questType);
    }

    function test_SignatureMint() public {
        // TestCUBE.CubeInputData[] memory cubeInputs = new TestCUBE.CubeInputData[](1);
        // TestCUBE.StepCompletionData[] memory steps = new TestCUBE.StepCompletionData[](1);
        // bytes32 txHashExample = 0x00000000;
        // steps[0] = TestCUBE.StepCompletionData(0x00000000, 1);
        // cubeInputs[0] = TestCUBE.CubeInputData(1, 1, "Test Wallet", steps);

        // bytes32[] memory signatures = new bytes32[](1);

		// bytes32 hashedInput1 = keccak256(
        //     abi.encodePacked(cubeInputs[0].questId, cubeInputs[0].userId, cubeInputs[0].walletName)
        // );
        // signatures[0] = hashedInput1.toEthSignedMessageHash();

        // cube.mintMultipleCubes(cubeInputs, signatures);
        // assertEq(cube.number(), 1);
    }
}
