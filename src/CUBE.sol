// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract DemoCUBE is ERC721, AccessControl, EIP712 {
    using ECDSA for bytes32;

    error TestCUBE__IsNotSigner();
    error TestCUBE__FeeNotEnough();
    error TestCUBE__SignatureAndCubesInputMismatch();
    error TestCUBE__WithdrawFailed();
    error TestCUBE__NonceAlreadyUsed();

    uint256 internal _nextTokenId;
    uint256 internal questCompletionIdCounter;

    bool public isMintingActive;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    bytes32 internal constant STEP_COMPLETION_HASH =
        keccak256("StepCompletionData(bytes32 stepTxHash,uint256 stepChainId)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 timestamp,uint256 nonce,string walletName,string tokenUri,address toAddress,StepCompletionData[] steps)StepCompletionData(bytes32 stepTxHash,uint256 stepChainId)"
    );

    mapping(uint256 => uint256) internal questIssueNumbers;
    mapping(uint256 => string) internal tokenURIs;
    mapping(address signerAddress => mapping(uint256 nonce => bool isConsumed)) internal nonces;

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

    struct CubeData {
        uint256 questId;
        uint256 userId;
        uint256 timestamp;
        uint256 nonce;
        string walletName;
        string tokenUri;
        address toAddress;
        StepCompletionData[] steps;
    }

    struct StepCompletionData {
        bytes32 stepTxHash;
        uint256 stepChainId;
    }

    constructor(
        string memory _name,
        string memory _symbol,
        string memory _signingDomain,
        string memory _signatureVersion
    ) EIP712(_signingDomain, _signatureVersion) ERC721(_name, _symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SIGNER_ROLE, msg.sender);
    }

    function setTokenURI(uint256 _tokenId, string memory newuri) external onlyRole(SIGNER_ROLE) {
        tokenURIs[_tokenId] = newuri;
    }

    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return tokenURIs[_tokenId];
    }

    function setIsAllowListActive(bool _isMintingActive) external onlyRole(SIGNER_ROLE) {
        isMintingActive = _isMintingActive;
    }

    function initializeQuest(
        uint256 questId,
        string[] memory communities,
        string memory title,
        Difficulty difficulty,
        QuestType questType
    ) external onlyRole(SIGNER_ROLE) {
        for (uint256 i = 0; i < communities.length;) {
            emit QuestCommunity(questId, communities[i]);
            unchecked {
                ++i;
            }
        }

        emit QuestMetadata(questId, questType, difficulty, title);

        delete questIssueNumbers[questId];
    }

    function _mintCube(CubeData calldata cubeInput, bytes calldata signature) internal {
        // check that signer has SIGNER_ROLE
        address signer = _getSigner(cubeInput, signature);
        if (!hasRole(SIGNER_ROLE, signer)) {
            revert TestCUBE__IsNotSigner();
        }

        bool isConsumedNonce = nonces[signer][cubeInput.nonce];
        if (isConsumedNonce) {
            revert TestCUBE__NonceAlreadyUsed();
        }

        // cache tokenId
        uint256 tokenId = _nextTokenId;

        uint256 issueNo = questIssueNumbers[cubeInput.questId];

        for (uint256 i = 0; i < cubeInput.steps.length;) {
            emit CubeTransaction(
                questCompletionIdCounter,
                cubeInput.steps[i].stepTxHash,
                cubeInput.steps[i].stepChainId
            );
            unchecked {
                ++i;
            }
        }

        tokenURIs[tokenId] = cubeInput.tokenUri;
        nonces[signer][cubeInput.nonce] = true;

        unchecked {
            ++questCompletionIdCounter;
            ++questIssueNumbers[cubeInput.questId];
            ++_nextTokenId;
        }

        _safeMint(msg.sender, tokenId);

        emit CubeClaim(
            cubeInput.questId,
            tokenId,
            issueNo,
            cubeInput.userId,
            cubeInput.timestamp,
            cubeInput.walletName
        );
    }

    function mintMultipleCubes(CubeData[] calldata cubeInputs, bytes[] calldata signatures)
        external
        payable
    {
        if (cubeInputs.length != signatures.length) {
            revert TestCUBE__SignatureAndCubesInputMismatch();
        }
        uint256 totalFee = 777 * cubeInputs.length;

        if (msg.value < totalFee) {
            revert TestCUBE__FeeNotEnough();
        }

        for (uint256 i = 0; i < cubeInputs.length;) {
            _mintCube(cubeInputs[i], signatures[i]);

            unchecked {
                ++i;
            }
        }
    }

    function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        if (!success) {
            revert TestCUBE__WithdrawFailed();
        }
    }

    function _getSigner(CubeData calldata data, bytes calldata signature)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CUBE_DATA_HASH,
                    data.questId,
                    data.userId,
                    data.timestamp,
                    data.nonce,
                    keccak256(bytes(data.walletName)),
                    keccak256(bytes(data.tokenUri)),
                    data.toAddress,
                    _encodeCompletedSteps(data.steps)
                )
            )
        );

        return digest.recover(signature);
    }

    function _encodeStep(StepCompletionData calldata step) public pure returns (bytes memory) {
        return abi.encode(STEP_COMPLETION_HASH, step.stepTxHash, step.stepChainId);
    }

    function _encodeCompletedSteps(StepCompletionData[] calldata steps)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory encodedSteps = new bytes32[](steps.length);

        // hash each step
        for (uint256 i = 0; i < steps.length; i++) {
            encodedSteps[i] = keccak256(_encodeStep(steps[i]));
        }

        // return hash of the concatenated steps
        return keccak256(abi.encodePacked(encodedSteps));
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    receive() external payable {}
}
