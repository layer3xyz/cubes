// SPDX-License-Identifier: Apache-2.0
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
    error CUBE__ExcessiveFeePayout();
    error CUBE__ExceedsContractBalance();

    uint256 internal s_nextTokenId;
    bool public s_isMintingActive;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(string txHash,string networkChainId)");
    bytes32 internal constant RECIPIENT_DATA_HASH =
        keccak256("FeeRecipient(address recipient,uint16 BPS)");
    bytes32 internal constant REWARD_DATA_HASH = keccak256(
        "RewardData(address tokenAddress,uint256 chainId,uint256 amount,uint256 tokenId,uint8 tokenType)"
    );
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 nonce,uint256 price,address toAddress,string walletProvider,string tokenURI,string embedOrigin,TransactionData[] transactions,FeeRecipient[] recipients,RewardData reward)FeeRecipient(address recipient,uint16 BPS)RewardData(address tokenAddress,uint256 chainId,uint256 amount,uint256 tokenId,uint8 tokenType)TransactionData(string txHash,string networkChainId)"
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

    enum TokenType {
        ERC20,
        ERC721,
        ERC1155,
        NATIVE
    }

    /// @notice Emitted when a new quest is initialized
    /// @param questId The unique identifier of the quest
    /// @param questType The type of the quest (QUEST, STREAK)
    /// @param difficulty The difficulty level of the quest (BEGINNER, INTERMEDIATE, ADVANCED)
    /// @param title The title of the quest
    /// @param tags An array of tags associated with the quest
    /// @param communities An array of communities associated with the quest
    event QuestMetadata(
        uint256 indexed questId,
        QuestType questType,
        Difficulty difficulty,
        string title,
        string[] tags,
        string[] communities
    );

    /// @notice Emitted when a CUBE is claimed
    /// @param questId The quest ID associated with the CUBE
    /// @param tokenId The token ID of the minted CUBE
    /// @param claimer Address of the CUBE claimer
    /// @param issueNumber The issue number of the CUBE
    /// @param walletProvider The name of the wallet provider used for claiming
    /// @param embedOrigin The origin of the embed associated with the CUBE
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        address indexed claimer,
        uint256 issueNumber,
        string walletProvider,
        string embedOrigin
    );

    /// @notice Emitted for each transaction associated with a CUBE claim
    /// This event is designed to support both EVM and non-EVM blockchains
    /// @param cubeTokenId The token ID of the Cube
    /// @param txHash The hash of the transaction
    /// @param networkChainId The network and chain ID of the transaction in the format <network>:<chain-id>
    event CubeTransaction(uint256 indexed cubeTokenId, string txHash, string networkChainId);

    /// @notice Emitted when there is a reward associated with a CUBE
    /// @param cubeTokenId The token ID of the CUBE giving the reward
    /// @param tokenAddress The token address of the reward
    /// @param chainId The blockchain chain ID where the transaction occurred
    /// @param amount The amount of the reward
    /// @param tokenId Token ID of the reward (only applicable for ERC721 and ERC1155)
    /// @param tokenType The type of reward token
    event TokenReward(
        uint256 indexed cubeTokenId,
        address indexed tokenAddress,
        uint256 indexed chainId,
        uint256 amount,
        uint256 tokenId,
        TokenType tokenType
    );

    /// @notice Emitted when a fee payout is made
    /// @param recipient The address of the payout recipient
    /// @param amount The amount of the payout
    event FeePayout(address indexed recipient, uint256 amount);

    /// @notice Emitted when the minting switch is turned on/off
    /// @param isActive The boolean showing if the minting is active or not
    event MintingSwitch(bool isActive);

    /// @notice Emitted when the contract balance is withdrawn by an admin
    /// @param amount The contract's balance that was withdrawn
    event ContractWithdrawal(uint256 amount);

    /// @dev Represents the data needed for minting a CUBE.
    /// @param questId The ID of the quest associated with the CUBE
    /// @param nonce A unique number to prevent replay attacks
    /// @param price The price paid for minting the CUBE
    /// @param toAddress The address where the CUBE will be minted
    /// @param walletProvider The wallet provider used for the transaction
    /// @param tokenURI The URI pointing to the CUBE's metadata
    /// @param embedOrigin The origin source of the CUBE's embed content
    /// @param transactions An array of transactions related to the CUBE
    /// @param recipients An array of recipients for fee payouts
    /// @param reward Data about the reward associated with the CUBE
    struct CubeData {
        uint256 questId;
        uint256 nonce;
        uint256 price;
        address toAddress;
        string walletProvider;
        string tokenURI;
        string embedOrigin;
        TransactionData[] transactions;
        FeeRecipient[] recipients;
        RewardData reward;
    }

    /// @dev Represents a recipient for fee distribution.
    /// @param recipient The address of the fee recipient
    /// @param BPS The basis points representing the fee percentage for the recipient
    struct FeeRecipient {
        address recipient;
        uint16 BPS;
    }

    /// @dev Contains data about the token rewards associated with a CUBE.
    /// @param tokenAddress The token address of the reward
    /// @param chainId The blockchain chain ID where the transaction occurred
    /// @param amount The amount of the reward
    /// @param tokenId The token ID
    /// @param tokenType The token type
    struct RewardData {
        address tokenAddress;
        uint256 chainId;
        uint256 amount;
        uint256 tokenId;
        TokenType tokenType;
    }

    /// @dev Contains data about a specific transaction related to a CUBE
    /// and is designed to support both EVM and non-EVM data.
    /// @param txHash The hash of the transaction
    /// @param networkChainId The network and chain ID of the transaction in the format <network>:<chain-id>
    struct TransactionData {
        string txHash;
        string networkChainId;
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
    ) external initializer {
        __ERC721_init(_tokenName, _tokenSymbol);
        __EIP712_init(_signingDomain, _signatureVersion);
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        s_isMintingActive = true;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /// @notice Authorizes an upgrade to a new contract implementation
    /// @dev Overrides the UUPSUpgradeable internal function with access control.
    /// @param newImplementation Address of the new contract implementation
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    /// @notice Retrieves the URI for a given token
    /// @dev Overrides the ERC721Upgradeable's tokenURI method.
    /// @param _tokenId The ID of the token
    /// @return _tokenURI The URI of the specified token
    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return s_tokenURIs[_tokenId];
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
        // Check if the minting function is currently active. If not, revert the transaction
        if (!s_isMintingActive) {
            revert CUBE__MintingIsNotActive();
        }
        // Ensure that each CubeData entry has a corresponding signature
        if (cubeData.length != signatures.length) {
            revert CUBE__SignatureAndCubesInputMismatch();
        }

        // Calculate the total fee required for all the minting requests
        uint256 totalFee;
        for (uint256 i = 0; i < cubeData.length;) {
            totalFee = totalFee + cubeData[i].price;
            unchecked {
                ++i;
            }
        }

        // Check if the sent value is at least equal to the calculated total fee
        if (msg.value < totalFee) {
            revert CUBE__FeeNotEnough();
        }

        // Loop through each CubeData entry and mint a CUBE
        for (uint256 i = 0; i < cubeData.length;) {
            _mintCube(cubeData[i], signatures[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Internal function to handle the logic of minting a single cube
    /// @dev Verifies the signer, handles nonce, transactions, referral payments, and minting.
    /// @param data The CubeData containing details of the minting
    /// @param signature The signature for verification
    function _mintCube(CubeData calldata data, bytes calldata signature) internal {
        // Cache the tokenId
        uint256 tokenId = s_nextTokenId;

        // Validate the signature to ensure the mint request is authorized
        _validateSignature(data, signature);

        // Iterate over all the transactions in the mint request and emit events
        for (uint256 i = 0; i < data.transactions.length;) {
            emit CubeTransaction(
                tokenId, data.transactions[i].txHash, data.transactions[i].networkChainId
            );
            unchecked {
                ++i;
            }
        }

        // Set the token URI for the CUBE
        s_tokenURIs[tokenId] = data.tokenURI;

        // Increment the counters for quest completion, issue numbers, and token IDs
        unchecked {
            ++s_questIssueNumbers[data.questId];
            ++s_nextTokenId;
        }

        // Process any payouts to fee recipients if applicable
        if (data.recipients.length > 0) {
            _processPayouts(data);
        }
        // Perform the actual minting of the CUBE
        _safeMint(data.toAddress, tokenId);

        // Emit an event indicating a CUBE has been claimed
        emit CubeClaim(
            data.questId,
            tokenId,
            data.toAddress,
            s_questIssueNumbers[data.questId],
            data.walletProvider,
            data.embedOrigin
        );

        if (data.reward.chainId != 0) {
            emit TokenReward(
                tokenId,
                data.reward.tokenAddress,
                data.reward.chainId,
                data.reward.amount,
                data.reward.tokenId,
                data.reward.tokenType
            );
        }
    }

    /// @notice Validates the signature for a Cube minting request
    /// @dev Ensures that the signature is from a valid signer and the nonce hasn't been used before
    /// @param data The CubeData struct containing minting details
    /// @param signature The signature to be validated
    function _validateSignature(CubeData calldata data, bytes calldata signature) internal {
        address signer = _getSigner(data, signature);
        if (!hasRole(SIGNER_ROLE, signer)) {
            revert CUBE__IsNotSigner();
        }
        if (s_nonces[data.nonce]) {
            revert CUBE__NonceAlreadyUsed();
        }
        s_nonces[data.nonce] = true;
    }

    /// @notice Processes fee payouts to specified recipients
    /// @dev Distributes a portion of the minting fee to designated addresses based on their Basis Points (BPS)
    /// @param data The CubeData struct containing payout details
    function _processPayouts(CubeData calldata data) internal {
        uint256 totalAmount;

        // max basis points is 10k (100%)
        uint16 maxBps = 10_000;
        uint256 contractBalance = address(this).balance;
        for (uint256 i = 0; i < data.recipients.length;) {
            if (data.recipients[i].BPS > maxBps) {
                revert CUBE__BPSTooHigh();
            }

            // Calculate the referral amount for each recipient
            uint256 referralAmount = (data.price * data.recipients[i].BPS) / maxBps;
            totalAmount = totalAmount + referralAmount;

            // Ensure the total payout does not exceed the cube price or contract balance
            if (totalAmount > data.price) {
                revert CUBE__ExcessiveFeePayout();
            }
            if (totalAmount > contractBalance) {
                revert CUBE__ExceedsContractBalance();
            }

            // Transfer the referral amount to the recipient
            address recipient = data.recipients[i].recipient;
            if (recipient != address(0)) {
                (bool success,) = recipient.call{value: referralAmount}("");
                if (!success) {
                    revert CUBE__TransferFailed();
                }
                emit FeePayout(recipient, referralAmount);
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Recovers the signer's address from the CubeData and its associated signature
    /// @dev Utilizes EIP-712 typed data hashing and ECDSA signature recovery
    /// @param data The CubeData struct containing the details of the minting request
    /// @param sig The signature associated with the CubeData
    /// @return The address of the signer who signed the CubeData
    function _getSigner(CubeData calldata data, bytes calldata sig)
        internal
        view
        returns (address)
    {
        bytes32 digest = _computeDigest(data);
        return digest.recover(sig);
    }

    /// @notice Internal function to compute the EIP712 digest for CubeData
    /// @dev Generates the digest that must be signed by the signer.
    /// @param data The CubeData to generate a digest for
    /// @return The computed EIP712 digest
    function _computeDigest(CubeData calldata data) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(_getStructHash(data)));
    }

    /// @notice Internal function to generate the struct hash for CubeData
    /// @dev Encodes the CubeData struct into a hash as per EIP712 standard.
    /// @param data The CubeData struct to hash
    /// @return A hash representing the encoded CubeData
    function _getStructHash(CubeData calldata data) internal pure returns (bytes memory) {
        return abi.encode(
            CUBE_DATA_HASH,
            data.questId,
            data.nonce,
            data.price,
            data.toAddress,
            _encodeString(data.walletProvider),
            _encodeString(data.tokenURI),
            _encodeString(data.embedOrigin),
            _encodeCompletedTxs(data.transactions),
            _encodeRecipients(data.recipients),
            _encodeReward(data.reward)
        );
    }

    /// @notice Encodes a string into a bytes32 hash
    /// @dev Used for converting strings into a consistent format for EIP712 encoding
    /// @param _string The string to be encoded
    /// @return The keccak256 hash of the encoded string
    function _encodeString(string calldata _string) internal pure returns (bytes32) {
        return keccak256(bytes(_string));
    }

    /// @notice Encodes a transaction data into a byte array
    /// @dev Used for converting transaction data into a consistent format for EIP712 encoding
    /// @param transaction The TransactionData struct to be encoded
    /// @return A byte array representing the encoded transaction data
    function _encodeTx(TransactionData calldata transaction) internal pure returns (bytes memory) {
        return abi.encode(
            TX_DATA_HASH,
            _encodeString(transaction.txHash),
            _encodeString(transaction.networkChainId)
        );
    }

    /// @notice Encodes an array of transaction data into a single bytes32 hash
    /// @dev Used to aggregate multiple transactions into a single hash for EIP712 encoding
    /// @param txData An array of TransactionData structs to be encoded
    /// @return A bytes32 hash representing the aggregated and encoded transaction data
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

    /// @notice Encodes a fee recipient data into a byte array
    /// @dev Used for converting fee recipient information into a consistent format for EIP712 encoding
    /// @param data The FeeRecipient struct to be encoded
    /// @return A byte array representing the encoded fee recipient data
    function _encodeRecipient(FeeRecipient calldata data) internal pure returns (bytes memory) {
        return abi.encode(RECIPIENT_DATA_HASH, data.recipient, data.BPS);
    }

    /// @notice Encodes an array of fee recipient data into a single bytes32 hash
    /// @dev Used to aggregate multiple fee recipient entries into a single hash for EIP712 encoding
    /// @param data An array of FeeRecipient structs to be encoded
    /// @return A bytes32 hash representing the aggregated and encoded fee recipient data
    function _encodeRecipients(FeeRecipient[] calldata data) internal pure returns (bytes32) {
        bytes32[] memory encodedRecipients = new bytes32[](data.length);
        for (uint256 i = 0; i < data.length;) {
            encodedRecipients[i] = keccak256(_encodeRecipient(data[i]));
            unchecked {
                ++i;
            }
        }

        return keccak256(abi.encodePacked(encodedRecipients));
    }

    /// @notice Encodes the reward data for a CUBE mint
    /// @param data An array of FeeRecipient structs to be encoded
    /// @return A bytes32 hash representing the encoded reward data
    function _encodeReward(RewardData calldata data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REWARD_DATA_HASH,
                data.tokenAddress,
                data.chainId,
                data.amount,
                data.tokenId,
                data.tokenType
            )
        );
    }

    /// @notice Enables or disables the minting process
    /// @dev Can only be called by an account with the default admin role.
    /// @param _isMintingActive Boolean indicating whether minting should be active
    function setIsMintingActive(bool _isMintingActive) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_isMintingActive = _isMintingActive;
        emit MintingSwitch(_isMintingActive);
    }

    /// @notice Withdraws the contract's balance to the message sender
    /// @dev Can only be called by an account with the default admin role.
    function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        if (!success) {
            revert CUBE__WithdrawFailed();
        }
        emit ContractWithdrawal(address(this).balance);
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
        string[] memory tags
    ) external onlyRole(SIGNER_ROLE) {
        emit QuestMetadata(questId, questType, difficulty, title, tags, communities);
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
}
