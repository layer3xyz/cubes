// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract TestCUBE is ERC721, Ownable, Multicall {
    using ECDSA for bytes32;

    uint256 private _nextTokenId;
    uint256 private questCompletionIdCounter = 0; // Add this line

    mapping(uint256 => uint256) private questIssueNumbers;

    enum QuestType {
        QUEST,
        JOURNEY
    }

    enum Difficulty {
        BEGINNER,
        INTERMEDIATE,
        ADVANCED
    }

    struct Community {
        uint16 communityId;
        string communityName;
    }

    event QuestMetadata(
        uint256 indexed questId,
        QuestType questType,
        uint8 difficulty,
        uint16[6] communityIds,
        string title
    );

    event CommunityMetadata(uint16 indexed communityId, string communityName);

    event QuestCompleted(
        uint256 indexed questId,
        uint256 indexed completionId,
        uint256 issueNumber,
        uint256 tokenId,
        uint256 userId,
        string walletName
    );

    event QuestTransaction(
        uint256 indexed completionId, bytes32 indexed stepTxHash, uint256 indexed stepChainId
    );

    struct CubeInputData {
        uint256 questId;
        uint256 userId;
        string walletName;
        StepCompletionData[] steps;
    }

    constructor() ERC721("TestCUBE", "TestCUBE") Ownable(msg.sender) {}

    function _baseURI() internal pure override returns (string memory) {
        return "https://l3img.b-cdn.net/ipfs/Qma6KFk7N3nP6LBxowuawcLfqQvmmCsWT1w2EMCihwAh7U?";
    }

    function initializeQuest(
        uint256 questId,
        Community[] memory communities,
        string memory title,
        uint8 difficulty,
        QuestType questType
    ) public {
        uint16[6] memory communityIds;

        for (uint256 i = 0; i < communities.length; i++) {
            communityIds[i] = communities[i].communityId;
            emit CommunityMetadata(communities[i].communityId, communities[i].communityName);
        }

        emit QuestMetadata(questId, questType, difficulty, communityIds, title);

        questIssueNumbers[questId] = 0;
    }

    struct StepCompletionData {
        bytes32 stepTxHash;
        uint256 stepChainId;
    }

    function verify(CubeInputData memory cubeInput, bytes memory signature) internal view {
        // Create the data hash
        bytes32 dataHash = keccak256(
            abi.encode(cubeInput.questId, cubeInput.userId, cubeInput.walletName, cubeInput.steps)
        );

        // Recover the signer's address
        address signer = ECDSA.recover(dataHash, signature);

        require(signer != owner(), "Invalid signature");
    }

    function _mintCube(CubeInputData memory cubeInput) internal {
        uint256 issueNo = questIssueNumbers[cubeInput.questId];
        _safeMint(msg.sender, _nextTokenId);
        questIssueNumbers[cubeInput.questId]++;

        emit QuestCompleted(
            cubeInput.questId,
            questCompletionIdCounter,
            issueNo,
            _nextTokenId,
            cubeInput.userId,
            cubeInput.walletName
        );

        for (uint256 i = 0; i < cubeInput.steps.length; i++) {
            emit QuestTransaction(
                questCompletionIdCounter,
                cubeInput.steps[i].stepTxHash,
                cubeInput.steps[i].stepChainId
            );
        }

        questCompletionIdCounter++;
        _nextTokenId++;
    }

    function mintMultipleCubes(CubeInputData[] memory cubeInputs, bytes[] memory signatures)
        public
        payable
    {
        uint256 totalFee = 777 * cubeInputs.length;

        // Fee check has been moved here
        require(msg.value >= totalFee, "Not enough fee sent!");

        // Loop over each CubeInputData in cubeInputs
        for (uint256 i = 0; i < cubeInputs.length; i++) {
            // Call the internal function _mintCube with each individual CubeInputData
            _mintCube(cubeInputs[i]);
        }
    }
}
