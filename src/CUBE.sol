// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract TestCUBE is ERC721, AccessControl {
    uint256 private _nextTokenId;
    uint256 private questCompletionIdCounter = 0;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    mapping(uint256 => uint256) private questIssueNumbers;
    mapping(uint256 => string) private tokenURIs;

    enum QuestType {
        QUEST,
        JOURNEY
    }

    enum Difficulty {
        BEGINNER,
        INTERMEDIATE,
        ADVANCED
    }

    event QuestMetadata(
        uint256 indexed questId, QuestType questType, Difficulty difficulty, string title
    );

    event QuestCommunity(uint256 indexed questId, string communityName);

    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        uint256 issueNumber,
        uint256 userId,
        uint256 completedAt,
        string walletName
    );

    event CubeTransaction(uint256 indexed tokenId, bytes32 indexed txHash, uint256 indexed chainId);

    struct Community {
        string communityName;
    }

    struct CubeInputData {
        uint256 questId;
        uint256 userId;
        string walletName;
        StepCompletionData[] steps;
        string tokenUri;
        uint256 timestamp;
    }

    constructor() ERC721("TestCUBE", "TestCUBE") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SIGNER_ROLE, msg.sender);
    }

    function setTokenURI(uint256 _tokenId, string memory newuri) public onlyRole(SIGNER_ROLE) {
        tokenURIs[_tokenId] = newuri;
    }

    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return tokenURIs[_tokenId];
    }

    function initializeQuest(
        uint256 questId,
        Community[] memory communities,
        string memory title,
        Difficulty difficulty,
        QuestType questType
    ) public onlyRole(SIGNER_ROLE) {
        for (uint256 i = 0; i < communities.length; i++) {
            emit QuestCommunity(questId, communities[i].communityName);
        }

        emit QuestMetadata(questId, questType, difficulty, title);

        questIssueNumbers[questId] = 0;
    }

    struct StepCompletionData {
        bytes32 stepTxHash;
        uint256 stepChainId;
    }

    function _recover(CubeInputData memory cubeInput, bytes memory signature)
        public
        pure
        returns (address)
    {
        // Create the data hash
        bytes32 hashedMessage = keccak256(_encodeCubeInput(cubeInput));
        bytes32 hashedMessageWithEthPrefix = MessageHashUtils.toEthSignedMessageHash(hashedMessage);

        // Recover the signer's address
        address signer = ECDSA.recover(hashedMessageWithEthPrefix, signature);

        return signer;
    }

    function verify(CubeInputData memory cubeInput, bytes memory signature) public view {
        // Recover the signer's address
        address signer = _recover(cubeInput, signature);

        require(
            hasRole(SIGNER_ROLE, signer),
            "Signature must be signed by an address with the SIGNER_ROLE"
        );
    }

    function _encodeCubeInput(CubeInputData memory cubeInput) public pure returns (bytes memory) {
        return abi.encodePacked(cubeInput.questId, cubeInput.userId, cubeInput.walletName);
    }

    function _mintCube(CubeInputData memory cubeInput, bytes memory signature) internal {
        // Verify the signature
        verify(cubeInput, signature);

        uint256 issueNo = questIssueNumbers[cubeInput.questId];
        _safeMint(msg.sender, _nextTokenId);
        questIssueNumbers[cubeInput.questId]++;

        emit CubeClaim(
            cubeInput.questId,
            _nextTokenId,
            issueNo,
            cubeInput.userId,
            cubeInput.timestamp,
            cubeInput.walletName
        );

        for (uint256 i = 0; i < cubeInput.steps.length; i++) {
            emit CubeTransaction(
                questCompletionIdCounter,
                cubeInput.steps[i].stepTxHash,
                cubeInput.steps[i].stepChainId
            );
        }

        tokenURIs[_nextTokenId] = cubeInput.tokenUri;

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
            _mintCube(cubeInputs[i], signatures[i]);
        }
    }

    // The following functions are overrides required by Solidity.

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
