// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract DemoCube2 is ERC721, AccessControl, EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    error TestCUBE__IsNotSigner();
    error TestCUBE__MintingIsNotActive();
    error TestCUBE__FeeNotEnough();
    error TestCUBE__SignatureAndCubesInputMismatch();
    error TestCUBE__WithdrawFailed();
    error TestCUBE__NonceAlreadyUsed();
    error TestCUBE___TransferFailed();
    error TestCUBE__BPSTooHigh();
    error TestCUBE__ExcessiveReferralPayout();

    uint256 internal s_nextTokenId;
    uint256 internal s_questCompletionIdCounter;
    uint16 constant MAX_BPS = 50_00;
    bool public s_isMintingActive;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(bytes32 txHash,uint256 chainId)");
    bytes32 internal constant REF_DATA_HASH =
        keccak256("ReferralData(address payable referrer,uint16 BPS,bytes32 data)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 completedAt,uint256 nonce,uint256 price,string tokenURI,string[] tags,address toAddress,TransactionData[] transactions,ReferralData[] refs)TransactionData(bytes32 txHash,uint256 chainId)ReferralData(address payable referrer,uint16 BPS,bytes32 data)"
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
    /// @param questType The type of the quest (QUEST, STREAK, etc.)
    /// @param difficulty The difficulty level of the quest (BEGINNER, INTERMEDIATE, ADVANCED)
    /// @param title The title of the quest
    event QuestMetadata(
        uint256 indexed questId, QuestType questType, Difficulty difficulty, string title
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
    /// @param tags An array of tags associated with the Cube
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        uint256 issueNumber,
        uint256 userId,
        uint256 completedAt,
        string[] tags
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
        uint256 completedAt;
        uint256 nonce;
        uint256 price;
        //string walletProvider;
        string tokenURI;
        //string embedOrigin;
        string[] tags;
        address toAddress;
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

    constructor(
        string memory _tokenName,
        string memory _tokenSymbol,
        string memory _signingDomain,
        string memory _signatureVersion
    )
        EIP712(_signingDomain, _signatureVersion)
        ERC721(_tokenName, _tokenSymbol)
        ReentrancyGuard()
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SIGNER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

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

    /// @notice Mints multiple cubes based on provided data and signatures
    /// @dev Checks if minting is active, matches cube data with signatures, and processes each mint.
    /// @param cubeData Array of CubeData structures containing minting information
    /// @param signatures Array of signatures corresponding to each CubeData
    function mintMultipleCubes(CubeData[] calldata cubeData, bytes[] calldata signatures)
        external
        payable
        nonReentrant
    {
        if (!s_isMintingActive) {
            revert TestCUBE__MintingIsNotActive();
        }
        if (cubeData.length != signatures.length) {
            revert TestCUBE__SignatureAndCubesInputMismatch();
        }

        uint256 totalFee;
        for (uint256 i = 0; i < cubeData.length;) {
            totalFee += cubeData[i].price;
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

    /// @notice Withdraws the contract's balance to the message sender
    /// @dev Can only be called by an account with the default admin role.
    function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        if (!success) {
            revert TestCUBE__WithdrawFailed();
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
        s_nonces[_data.nonce] = true;

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
            _data.tags
        );
    }

    function _validateSignature(CubeData calldata _data, bytes calldata _signature) internal {
        address signer = _getSigner(_data, _signature);
        if (!hasRole(SIGNER_ROLE, signer)) {
            revert TestCUBE__IsNotSigner();
        }

        bool isConsumedNonce = s_nonces[_data.nonce];
        if (isConsumedNonce) {
            revert TestCUBE__NonceAlreadyUsed();
        }
        s_nonces[_data.nonce] = true;
    }

    function _processReferrals(CubeData calldata _data) internal {
        uint256 totalReferralAmount = 0;
        for (uint256 i = 0; i < _data.refs.length;) {
            if (_data.refs[i].BPS > MAX_BPS) {
                revert TestCUBE__BPSTooHigh();
            }

            uint256 referralAmount = (_data.refs[i].BPS * _data.price) / 10_000;
            totalReferralAmount += referralAmount;
            if (totalReferralAmount > _data.price) {
                revert TestCUBE__ExcessiveReferralPayout();
            }
            if (totalReferralAmount > address(this).balance) {
                revert TestCUBE__ExcessiveReferralPayout();
            }
            address referrer = _data.refs[i].referrer;
            if (referrer != address(0)) {
                (bool success,) = referrer.call{value: referralAmount}("");
                if (!success) {
                    revert TestCUBE___TransferFailed();
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
            _data.completedAt,
            _data.nonce,
            _data.price,
            //_encodeString(_data.walletProvider),
            _encodeString(_data.tokenURI),
            //_encodeString(_data.embedOrigin),
            _encodeTags(_data.tags),
            _data.toAddress,
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

    /// @notice Checks if the contract implements an interface
    /// @dev Overrides the supportsInterface function of ERC721Upgradeable and AccessControlUpgradeable.
    /// @param interfaceId The interface identifier, as specified in ERC-165
    /// @return True if the contract implements the interface, false otherwise
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