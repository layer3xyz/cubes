// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ITokenType} from "./ITokenType.sol";
import {CUBE} from "../../CUBE.sol";

interface IFactory is ITokenType {
    function distributeRewards(
        uint256 questId,
        address token,
        address to,
        uint256 amount,
        uint256 rewardTokenId,
        TokenType tokenType,
        uint256 rakeBps
    ) external;

    function withdrawFunds(
        uint256 questId,
        address to,
        address token,
        uint256 tokenId,
        TokenType tokenType
    ) external;

    function createEscrow(
        uint256 questId,
        address admin,
        address[] memory whitelistedTokens,
        address treasury
    ) external;

    function updateEscrowAdmin(uint256 questId, address newAdmin) external;

    function addTokenToWhitelist(uint256 questId, address token) external;
    function removeTokenFromWhitelist(uint256 questId, address token) external;

    function initialize(address admin) external;
}
