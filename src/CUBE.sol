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
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC721Upgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {AccessControlUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IFactory} from "./escrow/interfaces/IFactory.sol";
import {ITokenType} from "./escrow/interfaces/ITokenType.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title CUBE
/// @dev Implementation of an NFT smart contract with EIP712 signatures.
/// The contract is upgradeable using OpenZeppelin's UUPSUpgradeable pattern.
/// @custom:oz-upgrades-from CUBE_V4
contract CUBE is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardUpgradeable,
    ITokenType
{
    using ECDSA for bytes32;

    error CUBE__IsNotSigner();
    error CUBE__MintingIsNotActive();
    error CUBE__FeeNotEnough();
    error CUBE__WithdrawFailed();
    error CUBE__NonceAlreadyUsed();
    error CUBE__TransferFailed();
    error CUBE__BPSTooHigh();
    error CUBE__ExcessiveFeePayout();
    error CUBE__ExceedsContractBalance();
    error CUBE__NativePaymentFailed();
    error CUBE__ERC20TransferFailed();
    error CUBE__L3TokenNotSet();
    error CUBE__L3PaymentsDisabled();
    error CUBE__TreasuryNotSet();
    error CUBE__InvalidAdminAddress();
    error CUBE__NoBalanceToSweep();

    uint256 public constant MAX_BPS = 1e4;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER");
    bytes32 public constant TREASURY_SWEEPER_ROLE = keccak256("TREASURY_SWEEPER");

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(string txHash,string networkChainId)");
    bytes32 internal constant RECIPIENT_DATA_HASH =
        keccak256("FeeRecipient(address recipient,uint16 BPS,uint8 recipientType)");
    bytes32 internal constant REWARD_DATA_HASH = keccak256(
        "RewardData(address tokenAddress,uint256 chainId,uint256 amount,uint256 tokenId,uint8 tokenType,uint256 rakeBps,address factoryAddress,address rewardRecipientAddress)"
    );
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 nonce,uint256 price,bool isNative,address toAddress,string walletProvider,string tokenURI,string embedOrigin,TransactionData[] transactions,FeeRecipient[] recipients,RewardData reward)FeeRecipient(address recipient,uint16 BPS,uint8 recipientType)RewardData(address tokenAddress,uint256 chainId,uint256 amount,uint256 tokenId,uint8 tokenType,uint256 rakeBps,address factoryAddress,address rewardRecipientAddress)TransactionData(string txHash,string networkChainId)"
    );

    bytes4 internal constant TRANSFER_ERC20 =
        bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));

    uint256 internal s_nextTokenId;
    bool public s_isMintingActive;

    mapping(uint256 => uint256) internal s_questIssueNumbers;
    mapping(uint256 => string) internal s_tokenURIs;
    mapping(uint256 nonce => bool isConsumed) internal s_nonces;
    mapping(uint256 => bool) internal s_quests;

    address public s_treasury;
    address public s_l3Token;
    bool public s_l3PaymentsEnabled;
    uint256 public s_treasuryBalanceL3;
    uint256 public s_treasuryBalanceNative;

    enum QuestType {
        QUEST,
        STREAK
    }

    enum Difficulty {
        BEGINNER,
        INTERMEDIATE,
        ADVANCED
    }

    enum FeeRecipientType {
        LAYER3,
        PUBLISHER,
        CREATOR,
        REFERRER
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
    /// @param isNative If the payment was made in native currency
    /// @param price The price paid for the CUBE
    /// @param issueNumber The issue number of the CUBE
    /// @param walletProvider The name of the wallet provider used for claiming
    /// @param embedOrigin The origin of the embed associated with the CUBE
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        address indexed claimer,
        bool isNative,
        uint256 price,
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
    /// @param rewardRecipientAddress The address of the reward recipient
    event TokenReward(
        uint256 indexed cubeTokenId,
        address indexed tokenAddress,
        uint256 indexed chainId,
        uint256 amount,
        uint256 tokenId,
        TokenType tokenType,
        address rewardRecipientAddress
    );

    /// @notice Emitted when a fee payout is made
    /// @param recipient The address of the payout recipient
    /// @param amount The amount of the payout
    /// @param isNative If the payout was made in native currency
    /// @param recipientType The type of recipient (LAYER3, PUBLISHER, CREATOR, REFERRER)
    event FeePayout(
        address indexed recipient, uint256 amount, bool isNative, FeeRecipientType recipientType
    );

    /// @notice Emitted when the minting switch is turned on/off
    /// @param isActive The boolean showing if the minting is active or not
    event MintingSwitch(bool isActive);

    /// @notice Emitted when the contract balance is withdrawn by an admin
    /// @param amount The contract's balance that was withdrawn
    event ContractWithdrawal(uint256 amount);

    /// @notice Emitted when a quest is disabled
    /// @param questId The ID of the quest that was disabled
    event QuestDisabled(uint256 indexed questId);

    /// @notice Emitted when the treasury address is updated
    /// @param newTreasury The new treasury address
    event UpdatedTreasury(address indexed newTreasury);

    /// @notice Emitted when the L3 token address is updated
    /// @param token The L3 token address
    event UpdatedL3Address(address indexed token);

    /// @notice Emitted when L3 payments are enabled or disabled
    /// @param enabled Boolean indicating whether L3 payments are enabled
    event L3PaymentsEnabled(bool enabled);

    /// @notice Emitted when the internal treasury balance is updated
    /// @param balance The balance of the treasury
    /// @param amount The amount transferred to the treasury
    /// @param isNative If the balance is in native currency or with L3
    event TreasuryBalanceUpdated(uint256 balance, uint256 amount, bool isNative);

    /// @notice Emitted when the cube mint fees are swept to the treasury
    /// @param nativeAmount The amount swept to the treasury with native currency
    /// @param l3Amount The amount swept to the treasury with L3
    event TreasurySwept(uint256 nativeAmount, uint256 l3Amount);

    /// @dev Represents the data needed for minting a CUBE.
    /// @param questId The ID of the quest associated with the CUBE
    /// @param nonce A unique number to prevent replay attacks
    /// @param price The price paid for minting the CUBE
    /// @param isNative If the price is paid in native currency or with L3
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
        bool isNative;
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
    /// @param recipientType The type of recipient (LAYER3, PUBLISHER, CREATOR, REFERRER)
    struct FeeRecipient {
        address recipient;
        uint16 BPS;
        FeeRecipientType recipientType;
    }

    /// @dev Contains data about the token rewards associated with a CUBE.
    /// @param tokenAddress The token address of the reward
    /// @param chainId The blockchain chain ID where the transaction occurred
    /// @param amount The amount of the reward
    /// @param tokenId The token ID
    /// @param tokenType The token type
    /// @param rakeBps The rake basis points
    /// @param factoryAddress The escrow factory address
    /// @param rewardRecipientAddress The address of the reward recipient
    struct RewardData {
        address tokenAddress;
        uint256 chainId;
        uint256 amount;
        uint256 tokenId;
        TokenType tokenType;
        uint256 rakeBps;
        address factoryAddress;
        address rewardRecipientAddress;
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

    /// @notice Returns the version of the CUBE smart contract
    function cubeVersion() external pure returns (string memory) {
        return "4.1";
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
        if (_admin == address(0)) revert CUBE__InvalidAdminAddress();
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

    /// @notice Checks whether a quest is active or not
    /// @param questId Unique identifier for the quest
    function isQuestActive(uint256 questId) public view returns (bool) {
        return s_quests[questId];
    }

    /// @notice Retrieves the URI for a given token
    /// @dev Overrides the ERC721Upgradeable's tokenURI method.
    /// @param _tokenId The ID of the token
    /// @return _tokenURI The URI of the specified token
    function tokenURI(uint256 _tokenId) public view override returns (string memory _tokenURI) {
        return s_tokenURIs[_tokenId];
    }

    /// @notice Mints a CUBE based on the provided data
    /// @param cubeData CubeData struct containing minting information
    /// @param signature Signature of the CubeData struct
    function mintCube(CubeData calldata cubeData, bytes calldata signature)
        external
        payable
        nonReentrant
    {
        // Check if the minting function is currently active. If not, revert the transaction
        if (!s_isMintingActive) {
            revert CUBE__MintingIsNotActive();
        }

        if (s_treasury == address(0)) {
            revert CUBE__TreasuryNotSet();
        }

        // Validate payment method and amount
        if (cubeData.isNative) {
            // Check if the sent value is at least equal to the price
            if (msg.value < cubeData.price) {
                revert CUBE__FeeNotEnough();
            }
        } else {
            // Check if L3 payments are enabled
            if (!s_l3PaymentsEnabled) {
                revert CUBE__L3PaymentsDisabled();
            }

            // Check if L3 token is set
            if (s_l3Token == address(0)) {
                revert CUBE__L3TokenNotSet();
            }
        }

        _mintCube(cubeData, signature);
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
        uint256 transactionsLength = data.transactions.length;
        for (uint256 i = 0; i < transactionsLength;) {
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

        // process payments
        data.isNative ? _processNativePayouts(data) : _processL3Payouts(data);

        // Perform the actual minting of the CUBE
        _safeMint(data.toAddress, tokenId);

        // Emit an event indicating a CUBE has been claimed
        emit CubeClaim(
            data.questId,
            tokenId,
            data.toAddress,
            data.isNative,
            data.price,
            s_questIssueNumbers[data.questId],
            data.walletProvider,
            data.embedOrigin
        );

        if (data.reward.chainId != 0) {
            if (data.reward.factoryAddress != address(0)) {
                IFactory(data.reward.factoryAddress).distributeRewards(
                    data.questId,
                    data.reward.tokenAddress,
                    data.reward.rewardRecipientAddress,
                    data.reward.amount,
                    data.reward.tokenId,
                    data.reward.tokenType,
                    data.reward.rakeBps
                );
            }

            emit TokenReward(
                tokenId,
                data.reward.tokenAddress,
                data.reward.chainId,
                data.reward.amount,
                data.reward.tokenId,
                data.reward.tokenType,
                data.reward.rewardRecipientAddress
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

    /// @notice Processes fee payouts to specified recipients when handling L3 payments
    /// @dev Distributes a portion of the minting fee to designated addresses based on their Basis Points (BPS)
    /// @param data The CubeData struct containing payout details
    function _processL3Payouts(CubeData calldata data) internal {
        // validate amounts
        (uint256[] memory payoutAmounts, uint256 totalAmount) = _calculatePayouts(data);

        // transfer mint fee from user to contract - using transferFrom()
        (bool success, bytes memory returnData) = s_l3Token.call(
            abi.encodeWithSelector(TRANSFER_ERC20, msg.sender, address(this), data.price)
        );
        if (!success || (returnData.length > 0 && !abi.decode(returnData, (bool)))) {
            revert CUBE__ERC20TransferFailed();
        }

        // process payouts to fee recipients
        uint256 recipientsLength = data.recipients.length;
        for (uint256 i = 0; i < recipientsLength;) {
            address recipient = data.recipients[i].recipient;
            uint256 amount = payoutAmounts[i];

            if (recipient != address(0) && amount > 0) {
                (success, returnData) = s_l3Token.call(
                    abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount)
                );
                if (!success || (returnData.length > 0 && !abi.decode(returnData, (bool)))) {
                    revert CUBE__ERC20TransferFailed();
                }
                emit FeePayout(recipient, amount, data.isNative, data.recipients[i].recipientType);
            }

            unchecked {
                ++i;
            }
        }

        // Transfer remaining amount to treasury
        uint256 treasuryAmount = data.price - totalAmount;
        s_treasuryBalanceL3 += treasuryAmount;
        emit TreasuryBalanceUpdated(s_treasuryBalanceL3, treasuryAmount, false);
    }

    /// @dev Calculates payout amounts for all recipients
    /// @param data The CubeData containing recipient information
    /// @return payoutAmounts Array of amounts to pay each recipient
    /// @return totalAmount Total amount to be paid to recipients
    function _calculatePayouts(CubeData calldata data)
        internal
        pure
        returns (uint256[] memory payoutAmounts, uint256 totalAmount)
    {
        uint256 recipientsLength = data.recipients.length;
        payoutAmounts = new uint256[](recipientsLength);
        totalAmount = 0;

        for (uint256 i = 0; i < recipientsLength;) {
            if (data.recipients[i].BPS > MAX_BPS) {
                revert CUBE__BPSTooHigh();
            }

            payoutAmounts[i] = (data.price * data.recipients[i].BPS) / MAX_BPS;
            totalAmount += payoutAmounts[i];

            if (totalAmount > data.price) {
                revert CUBE__ExcessiveFeePayout();
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Processes fee payouts to specified recipients when handling native payments
    /// @dev Distributes a portion of the minting fee to designated addresses based on their Basis Points (BPS)
    /// @param data The CubeData struct containing payout details
    function _processNativePayouts(CubeData calldata data) internal {
        uint256 totalReferrals;
        uint256 recipientsLength = data.recipients.length;

        if (recipientsLength > 0) {
            // max basis points is 10k (100%)
            uint256 contractBalance = address(this).balance;
            for (uint256 i = 0; i < recipientsLength;) {
                if (data.recipients[i].BPS > MAX_BPS) {
                    revert CUBE__BPSTooHigh();
                }

                // Calculate the referral amount for each recipient
                uint256 referralAmount = (data.price * data.recipients[i].BPS) / MAX_BPS;
                totalReferrals = totalReferrals + referralAmount;

                // Ensure the total payout does not exceed the cube price or contract balance
                if (totalReferrals > data.price) {
                    revert CUBE__ExcessiveFeePayout();
                }
                if (totalReferrals > contractBalance) {
                    revert CUBE__ExceedsContractBalance();
                }

                // Transfer the referral amount to the recipient
                address recipient = data.recipients[i].recipient;
                if (recipient != address(0)) {
                    (bool payoutSuccess,) = recipient.call{value: referralAmount}("");
                    if (!payoutSuccess) {
                        revert CUBE__TransferFailed();
                    }

                    emit FeePayout(
                        recipient, referralAmount, data.isNative, data.recipients[i].recipientType
                    );
                }
                unchecked {
                    ++i;
                }
            }
        }

        uint256 treasuryAmount = data.price - totalReferrals;
        s_treasuryBalanceNative += treasuryAmount;
        emit TreasuryBalanceUpdated(s_treasuryBalanceNative, treasuryAmount, true);
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
            data.isNative,
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
        return abi.encode(RECIPIENT_DATA_HASH, data.recipient, data.BPS, data.recipientType);
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
                data.tokenType,
                data.rakeBps,
                data.factoryAddress,
                data.rewardRecipientAddress
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

    /// @notice Sets a new treasury address
    /// @dev Can only be called by an account with the default admin role.
    /// @param _treasury Address of the new treasury to receive fees
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_treasury = _treasury;
        emit UpdatedTreasury(_treasury);
    }

    /// @notice Sets the address of the L3 token
    /// @dev Can only be called by an account with the default admin role.
    /// @param _l3 L3 token address
    function setL3TokenAddress(address _l3) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_l3Token = _l3;
        emit UpdatedL3Address(_l3);
    }

    /// @notice Enables or disables L3 payments
    /// @dev Can only be called by an account with the default admin role.
    /// @param _l3PaymentsEnabled Boolean indicating whether L3 payments should be enabled
    function setL3PaymentsEnabled(bool _l3PaymentsEnabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_l3PaymentsEnabled = _l3PaymentsEnabled;
        emit L3PaymentsEnabled(_l3PaymentsEnabled);
    }

    /// @notice Withdraws the contract's balance to the message sender
    /// @dev Can only be called by an account with the default admin role.
    function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 withdrawAmount = address(this).balance;
        (bool success,) = msg.sender.call{value: withdrawAmount}("");
        if (!success) {
            revert CUBE__WithdrawFailed();
        }
        emit ContractWithdrawal(withdrawAmount);
    }

    /// @notice Sweeps the contract's balances to the treasury.
    /// @dev Can only be called by an account with the treasury sweeper role.
    function sweepToTreasury() external onlyRole(TREASURY_SWEEPER_ROLE) {
        if (s_treasury == address(0)) revert CUBE__TreasuryNotSet();

        (uint256 l3Amount, uint256 nativeAmount) = (s_treasuryBalanceL3, s_treasuryBalanceNative);
        if (l3Amount == 0 && nativeAmount == 0) revert CUBE__NoBalanceToSweep();

        s_treasuryBalanceL3 = s_treasuryBalanceNative = 0;

        if (l3Amount > 0) {
            (bool successL3, bytes memory returnDataL3) = s_l3Token.call(
                abi.encodeWithSelector(IERC20.transfer.selector, s_treasury, l3Amount)
            );
            if (!successL3 || (returnDataL3.length > 0 && !abi.decode(returnDataL3, (bool)))) {
                revert CUBE__ERC20TransferFailed();
            }
        }

        if (nativeAmount > 0) {
            (bool successNative,) = payable(s_treasury).call{value: nativeAmount}("");
            if (!successNative) {
                revert CUBE__NativePaymentFailed();
            }
        }

        emit TreasurySwept(nativeAmount, l3Amount);
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
        s_quests[questId] = true;
        emit QuestMetadata(questId, questType, difficulty, title, tags, communities);
    }

    /// @notice Unpublishes and disables a quest
    /// @dev Can only be called by an account with the signer role
    /// @param questId Unique identifier for the quest
    function unpublishQuest(uint256 questId) external onlyRole(SIGNER_ROLE) {
        s_quests[questId] = false;
        emit QuestDisabled(questId);
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
