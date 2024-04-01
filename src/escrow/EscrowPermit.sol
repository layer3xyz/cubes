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

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Escrow} from "./Escrow.sol";
import {ITokenType} from "./interfaces/ITokenType.sol";

contract EscrowPermit is EIP712, ITokenType, Escrow {
    using ECDSA for bytes32;

    error EscrowPermit__SignerIsNotOwner();
    error EscrowPermit__NonceAlreadyUsed();
    error EscrowPermit__InsufficientClaimFee();
    error EscrowPermit__ClaimFeePayoutFailed();

    bytes32 internal constant HASH = keccak256(
        "ClaimData(address token,address to,uint256 amount,uint256 rewardTokenId,uint8 tokenType,uint256 rakeBps,uint256 claimFee,uint256 nonce)"
    );

    mapping(uint256 => bool) internal s_sigNonces;

    event ClaimFeePayout(address indexed payer, address indexed treasury, uint256 amount);
    event RewardClaimed(
        uint256 indexed taskId,
        address indexed to,
        uint256 amount,
        uint256 rewardTokenId,
        uint8 tokenType
    );

    struct ClaimData {
        uint256 taskId;
        address token;
        address to;
        uint256 amount;
        uint256 rewardTokenId;
        TokenType tokenType;
        uint256 rakeBps;
        uint256 claimFee;
        uint256 nonce;
    }

    constructor(address _owner, address[] memory tokenAddr, address treasury)
        Escrow(_owner, tokenAddr, treasury)
        EIP712("LAYER3", "1")
    {}

    function claimReward(ClaimData calldata data, bytes calldata signature) external payable {
        _validateSignature(data, signature);

        if (msg.value < data.claimFee) {
            revert EscrowPermit__InsufficientClaimFee();
        }
        (bool success,) = i_treasury.call{value: msg.value}("");
        if (!success) {
            revert EscrowPermit__ClaimFeePayoutFailed();
        }
        emit ClaimFeePayout(msg.sender, i_treasury, msg.value);

        // withdraw reward
        if (data.tokenType == TokenType.NATIVE) {
            _withdrawNative(data.to, data.amount, data.rakeBps);
        } else if (data.tokenType == TokenType.ERC20) {
            _withdrawERC20(data.token, data.to, data.amount, data.rakeBps);
        } else if (data.tokenType == TokenType.ERC721) {
            _withdrawERC721(data.token, data.to, data.rewardTokenId);
        } else if (data.tokenType == TokenType.ERC1155) {
            _withdrawERC1155(data.token, data.to, data.amount, data.rewardTokenId);
        } else {
            return;
        }
        emit RewardClaimed(
            data.taskId, data.to, data.amount, data.rewardTokenId, uint8(data.tokenType)
        );
    }

    function _validateSignature(ClaimData calldata data, bytes calldata signature) internal {
        address signer = _getSigner(data, signature);
        if (signer != owner()) {
            revert EscrowPermit__SignerIsNotOwner();
        }
        if (s_sigNonces[data.nonce]) {
            revert EscrowPermit__NonceAlreadyUsed();
        }
        s_sigNonces[data.nonce] = true;
    }

    function _computeDigest(ClaimData calldata data) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(_getStructHash(data)));
    }

    function _getStructHash(ClaimData calldata data) internal pure returns (bytes memory) {
        return abi.encode(
            HASH,
            data.token,
            data.to,
            data.amount,
            data.rewardTokenId,
            data.tokenType,
            data.rakeBps,
            data.claimFee
        );
    }

    function _getSigner(ClaimData calldata data, bytes calldata sig)
        internal
        view
        returns (address)
    {
        bytes32 digest = _computeDigest(data);
        return digest.recover(sig);
    }

    function _withdrawERC721(address token, address to, uint256 tokenId) internal {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }
        IERC721(token).safeTransferFrom(address(this), to, tokenId);
        emit EscrowERC721Transfer(token, to, tokenId);
    }

    function _withdrawERC1155(address token, address to, uint256 amount, uint256 tokenId)
        internal
    {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }

        IERC1155(token).safeTransferFrom(address(this), to, tokenId, amount, "");
        emit EscrowERC1155Transfer(token, to, amount, tokenId);
    }

    function _withdrawNative(address to, uint256 amount, uint256 rakeBps) internal {
        if (amount > escrowNativeBalance()) {
            revert Escrow__InsufficientEscrowBalance();
        }
        if (to == address(0)) {
            revert Escrow__ZeroAddress();
        }
        if (rakeBps > MAX_BPS) {
            revert Escrow__InvalidRakeBps();
        }

        uint256 rake = (amount * rakeBps) / MAX_BPS;
        if (rake > 0) {
            (bool rakeSuccess,) = payable(i_treasury).call{value: rake}("");
            if (!rakeSuccess) {
                revert Escrow__NativeRakeError();
            }
        }

        (bool rewardSuccess,) = payable(to).call{value: amount - rake, gas: GAS_CAP}("");
        if (!rewardSuccess) {
            revert Escrow__NativePayoutError();
        }

        emit EscrowNativeTransfer(to, amount, rake, i_treasury);
    }

    function _withdrawERC20(address token, address to, uint256 amount, uint256 rakeBps) internal {
        if (!s_whitelistedTokens[token]) {
            revert Escrow__TokenNotWhitelisted();
        }
        if (amount > escrowERC20Reserves(token)) {
            revert Escrow__InsufficientEscrowBalance();
        }
        if (rakeBps > MAX_BPS) {
            revert Escrow__InvalidRakeBps();
        }

        uint256 rake = (amount * rakeBps) / MAX_BPS;
        if (rake > 0) {
            _rakePayoutERC20(token, rake);
        }

        _safeTransferERC20(token, to, amount - rake);
        emit EscrowERC20Transfer(token, to, amount, rake, i_treasury);
    }
}
