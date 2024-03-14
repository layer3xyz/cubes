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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Escrow} from "./Escrow.sol";
import {CUBE} from "../CUBE.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";
import {IFactory} from "./interfaces/IFactory.sol";

contract Factory is IFactory, Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    error Factory__OnlyCallableByCUBE();
    error Factory__CUBEQuestNotActive();
    error Factory__NoQuestEscrowFound();
    error Factory__OnlyCallableByAdmin();
    error Factory__EscrowAlreadyExists();
    error Factory__ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    CUBE public immutable i_cube;
    mapping(uint256 => address) public s_escrows;
    mapping(uint256 => address) public s_escrow_admin;

    event EscrowRegistered(
        address indexed registror, address indexed escrowAddress, uint256 indexed questId
    );
    event TokenPayout(
        address indexed receiver,
        address indexed tokenAddress,
        uint256 indexed tokenId,
        uint256 amount,
        uint8 tokenType,
        uint256 questId
    );
    event EscrowWithdrawal(
        address indexed caller,
        address indexed receiver,
        address indexed tokenAddress,
        uint256 tokenId,
        uint256 amount,
        uint8 tokenType,
        uint256 questId
    );
    event EscrowAdminUpdated(
        address indexed updater, uint256 indexed questId, address indexed newAdmin
    );
    event TokenWhitelisted(address indexed token);
    event TokenRemovedFromWhitelist(address indexed token);

    modifier onlyAdmin(uint256 questId) {
        if (msg.sender != s_escrow_admin[questId] && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Factory__OnlyCallableByAdmin();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(CUBE cube) {
        i_cube = cube;
        _disableInitializers();
    }

    /// @notice Initializes the contract by setting up roles and linking to the CUBE contract.
    /// @param admin Address to be granted the default admin role.
    function initialize(address admin) external override initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Updates the admin of a specific escrow.
    /// @dev Can only be called by the current escrow admin.
    /// @param questId Identifier of the quest associated with the escrow.
    /// @param newAdmin Address of the new admin.
    function updateEscrowAdmin(uint256 questId, address newAdmin) external override {
        if (s_escrow_admin[questId] != msg.sender) {
            revert Factory__OnlyCallableByAdmin();
        }
        if (newAdmin == address(0)) {
            revert Factory__ZeroAddress();
        }
        s_escrow_admin[questId] = newAdmin;
        emit EscrowAdminUpdated(msg.sender, questId, newAdmin);
    }

    /// @notice Creates a new escrow for a quest.
    /// @dev Can only be called by an account with the default admin role.
    /// @param questId The quest the escrow should be created for.
    /// @param admin Admin of the new escrow.
    /// @param whitelistedTokens Array of addresses of tokens that are whitelisted for the escrow.
    /// @param treasury Address of the treasury where fees are sent.
    function createEscrow(
        uint256 questId,
        address admin,
        address[] calldata whitelistedTokens,
        address treasury
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (s_escrows[questId] != address(0)) {
            revert Factory__EscrowAlreadyExists();
        }

        s_escrow_admin[questId] = admin;
        address escrow = address(new Escrow(address(this), whitelistedTokens, treasury));
        s_escrows[questId] = escrow;

        emit EscrowRegistered(msg.sender, escrow, questId);
    }

    /// @notice Adds a token to the whitelist, allowing it to be used in the escrow.
    /// @param token The address of the token to whitelist.
    function addTokenToWhitelist(uint256 questId, address token)
        external
        override
        onlyAdmin(questId)
    {
        address escrow = s_escrows[questId];
        if (escrow == address(0)) {
            revert Factory__NoQuestEscrowFound();
        }

        IEscrow(escrow).addTokenToWhitelist(token);
        emit TokenWhitelisted(token);
    }

    /// @notice Removes a token from the whitelist.
    /// @param token The address of the token to remove from the whitelist.
    function removeTokenFromWhitelist(uint256 questId, address token)
        external
        override
        onlyAdmin(questId)
    {
        address escrow = s_escrows[questId];
        if (escrow == address(0)) {
            revert Factory__NoQuestEscrowFound();
        }

        IEscrow(escrow).removeTokenFromWhitelist(token);
        emit TokenRemovedFromWhitelist(token);
    }

    /// @notice Withdraws funds from the escrow associated with a quest.
    /// @dev Withdrawal can only be initiated by the escrow admin or an account with the default admin role.
    /// @param questId The quest the escrow is mapped to.
    /// @param to Recipient of the funds.
    /// @param token Address of the token to withdraw.
    /// @param tokenId Identifier of the token (for ERC721 and ERC1155).
    /// @param tokenType Type of the token being withdrawn.
    function withdrawFunds(
        uint256 questId,
        address to,
        address token,
        uint256 tokenId,
        TokenType tokenType
    ) external override onlyAdmin(questId) {
        // make sure quest is inactive
        if (i_cube.isQuestActive(questId)) {
            revert Factory__CUBEQuestNotActive();
        }
        address escrow = s_escrows[questId];
        if (escrow == address(0)) {
            revert Factory__NoQuestEscrowFound();
        }

        if (tokenType == TokenType.NATIVE) {
            uint256 escrowBalance = escrow.balance;
            IEscrow(escrow).withdrawNative(to, escrowBalance, 0);
            emit EscrowWithdrawal(
                msg.sender, to, address(0), 0, escrowBalance, uint8(tokenType), questId
            );
        } else if (tokenType == TokenType.ERC20) {
            uint256 erc20Amount = IEscrow(escrow).escrowERC20Reserves(token);
            IEscrow(escrow).withdrawERC20(token, to, erc20Amount, 0);
            emit EscrowWithdrawal(msg.sender, to, token, 0, erc20Amount, uint8(tokenType), questId);
        } else if (tokenType == TokenType.ERC721) {
            IEscrow(escrow).withdrawERC721(token, to, tokenId);
            emit EscrowWithdrawal(msg.sender, to, token, tokenId, 1, uint8(tokenType), questId);
        } else if (tokenType == TokenType.ERC1155) {
            uint256 erc1155Amount = IEscrow(escrow).escrowERC1155Reserves(token, tokenId);
            IEscrow(escrow).withdrawERC1155(token, to, tokenId, erc1155Amount);
            emit EscrowWithdrawal(
                msg.sender, to, token, tokenId, erc1155Amount, uint8(tokenType), questId
            );
        }
    }

    /// @notice Distributes rewards for a quest.
    /// @dev Can only be called by the CUBE contract.
    /// @param questId The quest the escrow is mapped to.
    /// @param token Address of the token for rewards.
    /// @param to Recipient of the rewards.
    /// @param amount Amount of tokens.
    /// @param rewardTokenId Token ID for ERC721 and ERC1155 rewards.
    /// @param tokenType Type of the token for rewards.
    /// @param rakeBps Basis points for the rake to be taken from the reward.
    function distributeRewards(
        uint256 questId,
        address token,
        address to,
        uint256 amount,
        uint256 rewardTokenId,
        TokenType tokenType,
        uint256 rakeBps
    ) external override {
        if (msg.sender != address(i_cube)) {
            revert Factory__OnlyCallableByCUBE();
        }
        address escrow = s_escrows[questId];
        if (escrow == address(0)) {
            revert Factory__NoQuestEscrowFound();
        }

        if (tokenType == TokenType.NATIVE) {
            IEscrow(escrow).withdrawNative(to, amount, rakeBps);
            emit TokenPayout(to, address(0), 0, amount, uint8(tokenType), questId);
        } else if (tokenType == TokenType.ERC20) {
            IEscrow(escrow).withdrawERC20(token, to, amount, rakeBps);
            emit TokenPayout(to, token, 0, amount, uint8(tokenType), questId);
        } else if (tokenType == TokenType.ERC721) {
            IEscrow(escrow).withdrawERC721(token, to, rewardTokenId);
            emit TokenPayout(to, token, rewardTokenId, 1, uint8(tokenType), questId);
        } else if (tokenType == TokenType.ERC1155) {
            IEscrow(escrow).withdrawERC1155(token, to, amount, rewardTokenId);
            emit TokenPayout(to, token, rewardTokenId, amount, uint8(tokenType), questId);
        }
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        virtual
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
    {}
}
