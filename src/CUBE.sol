// SPDX-License-Identifier: MIT
/*
.____                             ________
|    |   _____  ___.__. __________\_____  \
|    |   \__  \<   |  |/ __ \_  __ \_(__  <
|    |___ / __ \\___  \  ___/|  | \/       \
|_______ (____  / ____|\___  >__| /______  /
        \/    \/\/         \/            \/
*/

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
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title CUBE
/// @dev Implementation of an NFT smart contract with EIP712 signatures.
/// The contract is upgradeable using OpenZeppelin's UUPSUpgradeable pattern.
contract CUBE is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardUpgradeable
{
    using ECDSA for bytes32;

    error CUBE__IsNotSigner();
    error CUBE__MintingIsNotActive();
    error CUBE__FeeNotEnough();
    error CUBE__SignatureAndCubesInputMismatch();
    error CUBE__WithdrawFailed();
    error CUBE__NonceAlreadyUsed();
    error CUBE__TransferFailed();
    error CUBE__BPSTooHigh();
    error CUBE__ExcessiveReferralPayout();
    error CUBE__ExceedsContractBalance();

    uint256 internal s_nextTokenId;
    uint256 internal s_questCompletionIdCounter;
    bool public s_isMintingActive;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(bytes32 txHash,uint256 chainId)");
    bytes32 internal constant REF_DATA_HASH =
        keccak256("ReferralData(address referrer,uint16 BPS,bytes32 data)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 nonce,uint256 price,uint64 completedAt,address toAddress,string walletProvider,string tokenURI,string embedOrigin,TransactionData[] transactions,ReferralData[] refs)ReferralData(address referrer,uint16 BPS,bytes32 data)TransactionData(bytes32 txHash,uint256 chainId)"
    );

    mapping(uint256 => uint256) internal s_questIssueNumbers;
    mapping(uint256 => string) internal s_tokenURIs;
    mapping(uint256 nonce => bool isConsumed) internal s_nonces;

    enum QuestType {
        QUEST,
        STREAK
    }

    enum Difficulty {
        BEGINNER,
        INTERMEDIATE,
        ADVANCED
    }

    /// @notice Emitted when a new quest is initialized
    /// @param questId The unique identifier of the quest
    /// @param questType The type of the quest (QUEST, STREAK)
    /// @param difficulty The difficulty level of the quest (BEGINNER, INTERMEDIATE, ADVANCED)
    /// @param title The title of the quest
    /// @param tags An array of tags associated with the quest
    event QuestMetadata(
        uint256 indexed questId,
        QuestType questType,
        Difficulty difficulty,
        string title,
        string[] tags
    );

    /// @notice Emitted when a community is associated with a quest
    /// @param questId The unique identifier of the quest
    /// @param community The name of the community associated with the quest
    event QuestCommunity(uint256 indexed questId, string community);

    /// @notice Emitted when a Cube NFT is claimed
    /// @param questId The quest ID associated with the Cube
    /// @param tokenId The token ID of the minted Cube
    /// @param issueNumber The issue number of the Cube
    /// @param userId The ID of the user who claimed the Cube
    /// @param completedAt The timestamp when the Cube was claimed
    /// @param walletProvider The name of the wallet provider used for claiming
    /// @param embedOrigin The origin of the embed associated with the Cube
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        uint256 issueNumber,
        uint256 userId,
        uint64 completedAt,
        string walletProvider,
        string embedOrigin
    );

    /// @notice Emitted for each transaction associated with a Cube claim
    /// @param tokenId The token ID of the Cube
    /// @param txHash The hash of the transaction
    /// @param chainId The blockchain chain ID of the transaction
    event CubeTransaction(uint256 indexed tokenId, bytes32 indexed txHash, uint256 indexed chainId);

    /// @notice Emitted when a referral payout is made
    /// @param referrer The address of the referrer receiving the payout
    /// @param amount The amount of the referral payout
    /// @param data Additional data associated with the referral
    event ReferralPayout(address indexed referrer, uint256 amount, bytes32 data);

    struct CubeData {
        uint256 questId;
        uint256 userId;
        uint256 nonce;
        uint256 price;
        uint64 completedAt;
        address toAddress;
        string walletProvider;
        string tokenURI;
        string embedOrigin;
        TransactionData[] transactions;
        ReferralData[] refs;
    }

    struct ReferralData {
        address referrer;
        uint16 BPS;
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

    /// @notice Initializes the CUBE contract with necessary parameters
    /// @dev Sets up the ERC721 token with given name and symbol, and grants initial roles.
    /// @param _tokenName Name of the NFT collection
    /// @param _tokenSymbol Symbol of the NFT collection
    /// @param _signingDomain Domain used for EIP712 signing
    /// @param _signatureVersion Version of the EIP712 signature
    /// @param _admin Address to be granted the admin roles
    function initialize(
        string memory _tokenName,
        string memory _tokenSymbol,
        string memory _signingDomain,
        string memory _signatureVersion,
        address _admin
    ) public initializer {
        __ERC721_init(_tokenName, _tokenSymbol);
        __EIP712_init(_signingDomain, _signatureVersion);
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        s_isMintingActive = true;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SIGNER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
    }

    /// @notice Authorizes an upgrade to a new contract implementation
    /// @dev Overrides the UUPSUpgradeable internal function with access control.
    /// @param newImplementation Address of the new contract implementation
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    /// @notice Sets the URI for a given token
    /// @dev Can only be called by an account with the default admin role.
    /// @param _tokenId The ID of the token
    /// @param _uri The URI to be set for the token
    function setTokenURI(uint256 _tokenId, string memory _uri)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        s_tokenURIs[_tokenId] = _uri;
    }

    /// @notice Retrieves the URI for a given token
    /// @dev Overrides the ERC721Upgradeable's tokenURI method.
    /// @param _tokenId The ID of the token
    /// @return _tokenURI The URI of the specified token
    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return s_tokenURIs[_tokenId];
    }

    /// @notice Enables or disables the minting process
    /// @dev Can only be called by an account with the default admin role.
    /// @param _isMintingActive Boolean indicating whether minting should be active
    function setIsMintingActive(bool _isMintingActive) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_isMintingActive = _isMintingActive;
    }

    /// @notice Initializes a new quest with given parameters
    /// @dev Can only be called by an account with the signer role.
    /// @param questId Unique identifier for the quest
    /// @param communities Array of community names associated with the quest
    /// @param title Title of the quest
    /// @param difficulty Difficulty level of the quest
    /// @param questType Type of the quest
    function initializeQuest(
        uint256 questId,
        string[] memory communities,
        string memory title,
        Difficulty difficulty,
        QuestType questType,
        string[] calldata tags
    ) external onlyRole(SIGNER_ROLE) {
        for (uint256 i = 0; i < communities.length;) {
            emit QuestCommunity(questId, communities[i]);
            unchecked {
                ++i;
            }
        }

        emit QuestMetadata(questId, questType, difficulty, title, tags);
    }

    /// @notice Mints multiple cubes based on provided data and signatures
    /// @dev Checks if minting is active, matches cube data with signatures, and processes each mint.
    /// @param cubeData Array of CubeData structures containing minting information
    /// @param signatures Array of signatures corresponding to each CubeData
    function mintCubes(CubeData[] calldata cubeData, bytes[] calldata signatures)
        external
        payable
        nonReentrant
    {
        if (!s_isMintingActive) {
            revert CUBE__MintingIsNotActive();
        }
        if (cubeData.length != signatures.length) {
            revert CUBE__SignatureAndCubesInputMismatch();
        }

        uint256 totalFee;
        for (uint256 i = 0; i < cubeData.length;) {
            totalFee = totalFee + cubeData[i].price;
            unchecked {
                ++i;
            }
        }

        if (msg.value < totalFee) {
            revert CUBE__FeeNotEnough();
        }

        for (uint256 i = 0; i < cubeData.length;) {
            _mintCube(cubeData[i], signatures[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Withdraws the contract's balance to the message sender
    /// @dev Can only be called by an account with the default admin role.
    function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        if (!success) {
            revert CUBE__WithdrawFailed();
        }
    }

    /// @notice Internal function to handle the logic of minting a single cube
    /// @dev Verifies the signer, handles nonce, transactions, referral payments, and minting.
    /// @param _data The CubeData containing details of the minting
    /// @param _signature The signature for verification
    function _mintCube(CubeData calldata _data, bytes calldata _signature) internal {
        uint256 tokenId = s_nextTokenId;

        _validateSignature(_data, _signature);

        for (uint256 i = 0; i < _data.transactions.length;) {
            emit CubeTransaction(
                s_questCompletionIdCounter,
                _data.transactions[i].txHash,
                _data.transactions[i].chainId
            );
            unchecked {
                ++i;
            }
        }

        s_tokenURIs[tokenId] = _data.tokenURI;

        unchecked {
            ++s_questCompletionIdCounter;
            ++s_questIssueNumbers[_data.questId];
            ++s_nextTokenId;
        }

        if (_data.refs.length > 0) {
            _processReferrals(_data);
        }
        _safeMint(_data.toAddress, tokenId);

        emit CubeClaim(
            _data.questId,
            tokenId,
            s_questIssueNumbers[_data.questId],
            _data.userId,
            _data.completedAt,
            _data.walletProvider,
            _data.embedOrigin
        );
    }

    function _validateSignature(CubeData calldata _data, bytes calldata _signature) internal {
        address signer = _getSigner(_data, _signature);
        if (!hasRole(SIGNER_ROLE, signer)) {
            revert CUBE__IsNotSigner();
        }
        if (s_nonces[_data.nonce]) {
            revert CUBE__NonceAlreadyUsed();
        }
        s_nonces[_data.nonce] = true;
    }

    function _processReferrals(CubeData calldata _data) internal {
        uint256 totalReferralAmount;

        // max basis points is 10k (100%)
        uint16 maxBps = 10_000;
        uint256 contractBalance = address(this).balance;
        for (uint256 i = 0; i < _data.refs.length;) {
            if (_data.refs[i].BPS > maxBps) {
                revert CUBE__BPSTooHigh();
            }

            uint256 referralAmount = (_data.price * _data.refs[i].BPS) / maxBps;
            totalReferralAmount += referralAmount;
            if (totalReferralAmount > _data.price) {
                revert CUBE__ExcessiveReferralPayout();
            }
            if (totalReferralAmount > contractBalance) {
                revert CUBE__ExceedsContractBalance();
            }
            address referrer = _data.refs[i].referrer;
            if (referrer != address(0)) {
                (bool success,) = referrer.call{value: referralAmount}("");
                if (!success) {
                    revert CUBE__TransferFailed();
                }
                emit ReferralPayout(referrer, referralAmount, _data.refs[i].data);
            }
            unchecked {
                ++i;
            }
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

    function _computeDigest(CubeData calldata _data) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(_getStructHash(_data)));
    }

    function _getStructHash(CubeData calldata _data) internal pure returns (bytes memory) {
        return abi.encode(
            CUBE_DATA_HASH,
            _data.questId,
            _data.userId,
            _data.nonce,
            _data.price,
            _data.completedAt,
            _data.toAddress,
            _encodeString(_data.walletProvider),
            _encodeString(_data.tokenURI),
            _encodeString(_data.embedOrigin),
            _encodeCompletedTxs(_data.transactions),
            _encodeReferrals(_data.refs)
        );
    }

    function _encodeString(string calldata _string) internal pure returns (bytes32) {
        return keccak256(bytes(_string));
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

    /// @notice Checks if the contract implements an interface
    /// @dev Overrides the supportsInterface function of ERC721Upgradeable and AccessControlUpgradeable.
    /// @param interfaceId The interface identifier, as specified in ERC-165
    /// @return True if the contract implements the interface, false otherwise
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
