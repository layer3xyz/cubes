// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {console} from "forge-std/console.sol";

contract DemoCube2 is ERC721, AccessControl, EIP712 {
    using ECDSA for bytes32;

    error TestCUBE__MintingIsNotActive();
    error TestCUBE__IsNotSigner();
    error TestCUBE__FeeNotEnough();
    error TestCUBE__SignatureAndCubesInputMismatch();
    error TestCUBE__WithdrawFailed();
    error TestCUBE__NonceAlreadyUsed();

    uint256 internal _nextTokenId;
    uint256 internal questCompletionIdCounter;

    bool public isMintingActive = true;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(bytes32 txHash,uint256 chainId)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 completedAt,uint256 nonce,uint256 price,string walletProvider,string tokenURI,string embedOrigin,string[] tags,address toAddress,TransactionData[] transactions)TransactionData(bytes32 txHash,uint256 chainId)"
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
        string walletName,
        string embedOrigin,
        string[] tags
    );
    event CubeTransaction(uint256 indexed tokenId, bytes32 indexed txHash, uint256 indexed chainId);

    struct CubeData {
        uint256 questId;
        uint256 userId;
        uint256 completedAt;
        uint256 nonce;
        uint256 price;
        string walletProvider;
        string tokenURI;
        string embedOrigin;
        string[] tags;
        address toAddress;
        TransactionData[] transactions;
    }

    struct TransactionData {
        bytes32 txHash;
        uint256 chainId;
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

    function _mintCube(CubeData calldata _data, bytes calldata signature) internal {
        uint256 tokenId = _nextTokenId;
        uint256 issueNo = questIssueNumbers[_data.questId];

        // scope for signer, avoids stack too deep errors
        {
            address signer = _getSigner(_data, signature);
            if (!hasRole(SIGNER_ROLE, signer)) {
                revert TestCUBE__IsNotSigner();
            }

            bool isConsumedNonce = nonces[signer][_data.nonce];
            if (isConsumedNonce) {
                revert TestCUBE__NonceAlreadyUsed();
            }

            for (uint256 i = 0; i < _data.transactions.length;) {
                emit CubeTransaction(
                    questCompletionIdCounter,
                    _data.transactions[i].txHash,
                    _data.transactions[i].chainId
                );
                unchecked {
                    ++i;
                }
            }

            tokenURIs[tokenId] = _data.tokenURI;
            nonces[signer][_data.nonce] = true;
        }

        unchecked {
            ++questCompletionIdCounter;
            ++questIssueNumbers[_data.questId];
            ++_nextTokenId;
        }
        _safeMint(_data.toAddress, tokenId);

        emit CubeClaim(
            _data.questId,
            tokenId,
            issueNo,
            _data.userId,
            _data.completedAt,
            _data.walletProvider,
            _data.embedOrigin,
            _data.tags
        );
    }

    function mintMultipleCubes(CubeData[] calldata cubeData, bytes[] calldata signatures)
        external
        payable
    {
        if (!isMintingActive) {
            revert TestCUBE__MintingIsNotActive();
        }
        if (cubeData.length != signatures.length) {
            revert TestCUBE__SignatureAndCubesInputMismatch();
        }

        uint256 totalFee;
        for (uint256 i = 0; i < cubeData.length;) {
            totalFee = totalFee + cubeData[i].price;
            unchecked {
                ++i;
            }
        }

        if (msg.value < totalFee) {
            revert TestCUBE__FeeNotEnough();
        }

        for (uint256 i = 0; i < cubeData.length;) {
            _mintCube(cubeData[i], signatures[i]);
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
        bytes32 digest = _computeDigest(data);
        console.logBytes32(digest);
        console.logBytes(signature);
        return digest.recover(signature);
    }

    function _computeDigest(CubeData calldata data) internal view returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedTags = _encodeTags(data.tags);

        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CUBE_DATA_HASH,
                    data.questId,
                    data.userId,
                    data.completedAt,
                    data.nonce,
                    data.price,
                    keccak256(bytes(data.walletProvider)),
                    keccak256(bytes(data.tokenURI)),
                    keccak256(bytes(data.embedOrigin)),
                    encodedTags,
                    data.toAddress,
                    encodedTxs
                )
            )
        );
    }

    function _encodeTx(TransactionData calldata transaction) internal pure returns (bytes memory) {
        return abi.encode(TX_DATA_HASH, transaction.txHash, transaction.chainId);
    }

    function _encodeCompletedTxs(TransactionData[] calldata txData)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory encodedTxs = new bytes32[](txData.length);
        for (uint256 i = 0; i < txData.length;) {
            encodedTxs[i] = keccak256(_encodeTx(txData[i]));
            unchecked {
                ++i;
            }
        }

        return keccak256(abi.encodePacked(encodedTxs));
    }

    function _encodeTags(string[] calldata tags) internal pure returns (bytes32) {
        bytes32[] memory encodedTxs = new bytes32[](tags.length);
        for (uint256 i = 0; i < tags.length;) {
            encodedTxs[i] = keccak256(abi.encodePacked(tags[i]));
            unchecked {
                ++i;
            }
        }

        return keccak256(abi.encodePacked(encodedTxs));
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
