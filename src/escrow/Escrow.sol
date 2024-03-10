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

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";

contract Escrow is IEscrow, AccessControl, ERC721Holder, ERC1155Holder {
    error Escrow__TokenNotWhitelisted();
    error Escrow__InsufficientEscrowBalance();
    error Escrow__MustBeOwner();
    error Escrow__ZeroAddress();
    error Escrow__NativeRakeError();
    error Escrow__NativePayoutError();

    event EscrowERC20Transfer(
        address token, address to, uint256 amount, uint256 rake, address rakePayoutAddress
    );
    event NativeTransfer(
        address indexed to, uint256 indexed amount, uint256 indexed rake, address rakePayoutAddress
    );

    bytes4 private constant TRANSFER_ERC20 = bytes4(keccak256(bytes("transfer(address,uint256)")));

    address public s_owner;
    address public immutable i_treasury;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    mapping(address => bool) public s_whitelistedTokens;

    modifier onlyOwner() {
        if (msg.sender != s_owner) {
            revert Escrow__MustBeOwner();
        }
        _;
    }

    /// @notice Initializes the escrow contract with specified admin, whitelisted tokens, and treasury address.
    /// @param admin The address to be given the default admin role.
    /// @param tokenAddr An array of addresses of tokens to whitelist upon initialization.
    /// @param treasury The address of the treasury for receiving rake payments.
    constructor(address admin, address[] memory tokenAddr, address treasury) {
        s_owner = msg.sender;
        i_treasury = treasury;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        for (uint256 i = 0; i < tokenAddr.length;) {
            s_whitelistedTokens[tokenAddr[i]] = true;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Changes the owner of the escrow.
    /// @param newOwner The address of the new owner.
    function changeOwner(address newOwner) external onlyOwner {
        s_owner = newOwner;
    }

    /// @notice Adds a token to the whitelist, allowing it to be used in the escrow.
    /// @param token The address of the token to whitelist.
    function addTokenToWhitelist(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_whitelistedTokens[token] = true;
    }

    /// @notice Removes a token from the whitelist.
    /// @param token The address of the token to remove from the whitelist.
    function removeTokenFromWhitelist(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        s_whitelistedTokens[token] = false;
    }

    /// @notice Returns the ERC20 token balance held in escrow.
    /// @param token The address of the token.
    /// @return The balance of the specified token held in escrow.
    function escrowERC20Reserves(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /// @notice Returns the ERC1155 token balance held in escrow for a specific tokenId.
    /// @param token The address of the token.
    /// @param tokenId The ID of the token.
    /// @return The balance of the specified token ID held in escrow.
    function escrowERC1155Reserves(address token, uint256 tokenId)
        external
        view
        returns (uint256)
    {
        return IERC1155(token).balanceOf(address(this), tokenId);
    }

    /// @notice Returns the native balance of the escrow smart contract
    function escrowNativeBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Returns the ERC721 token balance held in escrow.
    function escrowERC721BalanceOf(address token) external view returns (uint256) {
        return IERC721(token).balanceOf(address(this));
    }

    /// @notice Withdraws ERC20 tokens from the escrow to a specified address.
    /// @dev Can only be called by the owner. Applies a rake before sending to the recipient.
    /// @param token The token address.
    /// @param to The recipient address.
    /// @param amount The amount to withdraw.
    /// @param rakeBps The basis points of the total amount to be taken as rake.
    function withdrawERC20(address token, address to, uint256 amount, uint256 rakeBps)
        external
        onlyOwner
    {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }

        if (amount > this.escrowERC20Reserves(token)) {
            revert Escrow__InsufficientEscrowBalance();
        }

        // rake payment in basis points
        uint256 rake = amount * rakeBps / 10_000;
        _rakePayoutERC20(token, rake);

        _safeTransferERC20(token, to, amount - rake);
        emit EscrowERC20Transfer(token, to, amount, rake, i_treasury);
    }

    function _rakePayoutERC20(address token, uint256 amount) internal {
        _safeTransferERC20(token, i_treasury, amount);
    }

    function _safeTransferERC20(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(TRANSFER_ERC20, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    /// @notice Withdraws ERC721 tokens from the escrow to a specified address.
    /// @dev Can only be called by the owner.
    /// @param token The token address.
    /// @param to The recipient address.
    /// @param tokenId The token ID to withdraw.
    function withdrawERC721(address token, address to, uint256 tokenId) external onlyOwner {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }
        IERC721(token).safeTransferFrom(address(this), to, tokenId);
    }

    /// @notice Withdraws ERC1155 tokens from the escrow to a specified address.
    /// @dev Can only be called by the owner.
    /// @param token The token address.
    /// @param to The recipient address.
    /// @param amount The amount to withdraw.
    /// @param tokenId The token ID to withdraw.
    function withdrawERC1155(address token, address to, uint256 amount, uint256 tokenId)
        external
        onlyOwner
    {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }

        IERC1155(token).safeTransferFrom(address(this), to, tokenId, amount, "0x00");
    }

    /// @notice Withdraws native tokens from the escrow to a specified address.
    /// @dev Can only be called by the owner.
    /// @param to The recipient address.
    /// @param amount The amount to withdraw.
    /// @param rakeBps The basis points of the total amount to be taken as rake.
    function withdrawNative(address to, uint256 amount, uint256 rakeBps) external onlyOwner {
        if (amount > this.escrowNativeBalance()) {
            revert Escrow__InsufficientEscrowBalance();
        }
        if (to == address(0)) {
            revert Escrow__ZeroAddress();
        }

        // rake payment
        uint256 rake = amount * rakeBps / 10_000;
        (bool rakeSuccess,) = payable(i_treasury).call{value: rake}("");
        if (!rakeSuccess) {
            revert Escrow__NativeRakeError();
        }

        (bool rewardSuccess,) = payable(to).call{value: amount - rake}("");
        if (!rewardSuccess) {
            revert Escrow__NativePayoutError();
        }

        emit NativeTransfer(to, amount, rake, i_treasury);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl, ERC1155Holder)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    fallback() external payable {}
    receive() external payable {}
}
