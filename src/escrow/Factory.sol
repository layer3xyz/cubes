// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Escrow} from "./Escrow.sol";
import {CUBE} from "../CUBE.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";
import {IFactory} from "./interfaces/IFactory.sol";

contract Factory is IFactory, AccessControl {
    error Factory__OnlyCallableByCUBE();
    error Factory__CUBEQuestNotActive();
    error Factory__NoQuestEscrowFound();
    error Factory__OnlyCallableByEscrowAdmin();
    error Factory__EscrowAlreadyExists();

    CUBE immutable i_cube;
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

    constructor(CUBE _cube, address admin) {
        i_cube = _cube;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // INVARIANT: only callable by escrow admin
    function updateEscrowAdmin(uint256 questId, address newAdmin) external {
        if (s_escrow_admin[questId] != msg.sender) {
            revert Factory__OnlyCallableByEscrowAdmin();
        }
        s_escrow_admin[questId] = newAdmin;
    }

    function createEscrow(
        uint256 questId,
        address admin,
        address[] memory whitelistedTokens,
        address treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (s_escrows[questId] != address(0)) {
            revert Factory__EscrowAlreadyExists();
        }

        s_escrow_admin[questId] = admin;
        address escrow = address(new Escrow(admin, whitelistedTokens, treasury));
        s_escrows[questId] = escrow;

        emit EscrowRegistered(msg.sender, escrow, questId);
    }

    function withdrawFunds(
        uint256 questId,
        address to,
        address token,
        uint256 tokenId,
        TokenType tokenType
    ) external {
        // make sure quest is inactive
        if (i_cube.isQuestActive(questId)) {
            revert Factory__CUBEQuestNotActive();
        }
        address escrow = s_escrows[questId];
        if (escrow == address(0)) {
            revert Factory__NoQuestEscrowFound();
        }

        if (msg.sender != s_escrow_admin[questId] && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Factory__OnlyCallableByEscrowAdmin();
        }

        if (tokenType == TokenType.NATIVE) {
            IEscrow(escrow).withdrawNative(to, escrow.balance, 0);
        }
        if (tokenType == TokenType.ERC20) {
            uint256 erc20Amount = IEscrow(escrow).escrowERC20Reserves(token);
            IEscrow(escrow).withdrawERC20(token, to, erc20Amount, 0);
        }
        if (tokenType == TokenType.ERC721) {
            IEscrow(escrow).withdrawERC721(token, to, tokenId);
        }
        if (tokenType == TokenType.ERC1155) {
            uint256 erc1155Amount = IEscrow(escrow).escrowERC1155Reserves(token, tokenId);
            IEscrow(escrow).withdrawERC1155(token, to, tokenId, erc1155Amount);
        }
    }

    function distributeRewards(
        uint256 questId,
        address token,
        address to,
        uint256 amount,
        uint256 rewardTokenId,
        TokenType tokenType,
        uint256 rakeBps
    ) external returns (bool success) {
        if (msg.sender != address(i_cube)) {
            revert Factory__OnlyCallableByCUBE();
        }

        if (tokenType == TokenType.NATIVE) {
            IEscrow(s_escrows[questId]).withdrawNative(to, amount, rakeBps);
            emit TokenPayout(to, address(0), 0, amount, 0, questId);
        }
        if (tokenType == TokenType.ERC20) {
            IEscrow(s_escrows[questId]).withdrawERC20(token, to, amount, rakeBps);
            emit TokenPayout(to, token, 0, amount, 1, questId);
        }
        if (tokenType == TokenType.ERC721) {
            IEscrow(s_escrows[questId]).withdrawERC721(token, to, rewardTokenId);
            emit TokenPayout(to, token, rewardTokenId, 1, 2, questId);
        }
        if (tokenType == TokenType.ERC1155) {
            IEscrow(s_escrows[questId]).withdrawERC1155(token, to, amount, rewardTokenId);
            emit TokenPayout(to, token, rewardTokenId, amount, 3, questId);
        }
    }
}
