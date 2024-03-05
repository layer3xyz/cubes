// SPDX-License-Identifier: MIT
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

    event ERC20Transfer(
        address token, address to, uint256 amount, uint256 rake, address rakePayoutAddress
    );
    event ERC721Transfer(address indexed token, address indexed to, uint256 indexed tokenId);
    event ERC1155Transfer(
        address indexed token, address indexed to, uint256 indexed tokenId, uint256 amount
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

    constructor(address admin, address[] memory tokenAddr, address treasury) {
        s_owner = msg.sender;
        i_treasury = treasury;

        _grantRole(ADMIN_ROLE, admin);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        for (uint256 i = 0; i < tokenAddr.length;) {
            s_whitelistedTokens[tokenAddr[i]] = true;
            unchecked {
                ++i;
            }
        }
    }

    function changeOwner(address newOwner) external onlyOwner {
        s_owner = newOwner;
    }

    function addTokenToWhitelist(address token) external onlyRole(ADMIN_ROLE) {
        s_whitelistedTokens[token] = true;
    }

    function removeTokenFromWhitelist(address token) external onlyRole(ADMIN_ROLE) {
        s_whitelistedTokens[token] = false;
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// VIEW FUNCTIONS ////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////

    function escrowERC20Reserves(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    function escrowERC1155Reserves(address token, uint256 tokenId)
        external
        view
        returns (uint256)
    {
        return IERC1155(token).balanceOf(address(this), tokenId);
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// WITHDRAWALS ///////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////

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
        emit ERC20Transfer(token, to, amount, rake, i_treasury);
    }

    function _rakePayoutERC20(address token, uint256 amount) internal {
        _safeTransferERC20(token, i_treasury, amount);
    }

    function _safeTransferERC20(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(TRANSFER_ERC20, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function withdrawERC721(address token, address to, uint256 tokenId) external onlyOwner {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }
        IERC721(token).safeTransferFrom(address(this), to, tokenId);

        emit ERC721Transfer(token, to, tokenId);
    }

    function withdrawERC1155(address token, address to, uint256 amount, uint256 tokenId)
        external
        onlyOwner
    {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }

        IERC1155(token).safeTransferFrom(address(this), to, tokenId, amount, "0x00");
        emit ERC1155Transfer(token, to, tokenId, amount);
    }

    function withdrawNative(address to, uint256 amount, uint256 rakeBps) external onlyOwner {
        if (amount > address(this).balance) {
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
