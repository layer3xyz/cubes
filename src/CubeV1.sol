// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {EIP712Upgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC721Upgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {AccessControlUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {console} from "forge-std/console.sol";

contract CubeV1 is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable
{
    using ECDSA for bytes32;

    error TestCUBE__IsNotSigner();
    error TestCUBE__MintingIsNotActive();
    error TestCUBE__FeeNotEnough();
    error TestCUBE__SignatureAndCubesInputMismatch();
    error TestCUBE__WithdrawFailed();
    error TestCUBE__NonceAlreadyUsed();
    error TestCUBE___Transfer_Failed();

    uint256 internal _nextTokenId;
    uint256 internal questCompletionIdCounter;

    bool public isMintingActive;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(bytes32 txHash,uint256 chainId)");
    bytes32 internal constant REF_DATA_HASH =
        keccak256("ReferralData(address payable referrer,uint256 BPS,bytes32 data)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 completedAt,uint256 nonce,uint256 price,string walletProvider,string tokenURI,string embedOrigin,string[] tags,address toAddress,TransactionData[] transactions,ReferralData[] refs)TransactionData(bytes32 txHash,uint256 chainId)ReferralData(address payable referrer,uint256 BPS,bytes32 data)"
    );

    mapping(uint256 => uint256) internal questIssueNumbers;
    mapping(uint256 => string) internal tokenURIs;
    mapping(address signerAddress => mapping(uint256 nonce => bool isConsumed)) internal nonces;

    enum QuestType {
        QUEST,
        STREAK
    }

    enum Difficulty {
        BEGINNER,
        INTERMEDIATE,
        ADVANCED
    }

    event QuestMetadata(
        uint256 indexed questId, QuestType questType, Difficulty difficulty, string title
    );
    event QuestCommunity(uint256 indexed questId, string community);
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
        ReferralData[] refs;
    }

    struct ReferralData {
        address referrer;
        uint256 BPS;
        bytes32 data;
    }

    struct TransactionData {
        bytes32 txHash;
        uint256 chainId;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory _name,
        string memory _symbol,
        string memory _signingDomain,
        string memory _signatureVersion,
        address _admin
    ) public initializer {
        __ERC721_init(_name, _symbol);
        __EIP712_init(_signingDomain, _signatureVersion);
        __AccessControl_init();
        __UUPSUpgradeable_init();
        isMintingActive = true;

        // TODO: update these so they're not msg.sender?
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SIGNER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function setTokenURI(uint256 _tokenId, string memory newuri) external onlyRole(SIGNER_ROLE) {
        tokenURIs[_tokenId] = newuri;
    }

    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return tokenURIs[_tokenId];
    }

    function setIsMintingActive(bool _isMintingActive) external onlyRole(SIGNER_ROLE) {
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

        for (uint256 i = 0; i < _data.refs.length;) {
            uint256 referralAmount = _data.price * _data.refs[i].BPS / 10_000;
            (bool success,) = _data.refs[i].referrer.call{value: referralAmount}("");
            if (!success) {
                revert TestCUBE___Transfer_Failed();
            }
            unchecked {
                ++i;
            }
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
        return digest.recover(signature);
    }

    function _computeDigest(CubeData calldata data) public view returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedTags = _encodeTags(data.tags);
        bytes32 encodedRefs = _encodeReferrals(data.refs);

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
                    encodedTxs,
                    encodedRefs
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

    function _encodeRef(ReferralData calldata ref) internal pure returns (bytes memory) {
        return abi.encode(REF_DATA_HASH, ref.referrer, ref.BPS, ref.data);
    }

    function _encodeReferrals(ReferralData[] calldata refData) internal pure returns (bytes32) {
        bytes32[] memory encodedRefs = new bytes32[](refData.length);
        for (uint256 i = 0; i < refData.length;) {
            encodedRefs[i] = keccak256(_encodeRef(refData[i]));
            unchecked {
                ++i;
            }
        }

        return keccak256(abi.encodePacked(encodedRefs));
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
        override(ERC721Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    receive() external payable {}
}
