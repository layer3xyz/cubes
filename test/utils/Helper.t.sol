// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Vm} from "forge-std/Test.sol";

import {CUBE} from "../../src/CUBE.sol";
import {MockERC20} from "../mock/MockERC20.sol";
import {MockERC721} from "../mock/MockERC721.sol";
import {MockERC1155} from "../mock/MockERC1155.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract Helper is CUBE {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    function getStructHash(CubeData calldata data) public pure returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedRefs = _encodeRecipients(data.recipients);
        bytes32 encodedReward = _encodeReward(data.reward);

        return keccak256(
            abi.encode(
                CUBE_DATA_HASH,
                data.questId,
                data.nonce,
                data.price,
                data.isNative,
                data.toAddress,
                keccak256(bytes(data.walletProvider)),
                keccak256(bytes(data.tokenURI)),
                keccak256(bytes(data.embedOrigin)),
                encodedTxs,
                encodedRefs,
                encodedReward
            )
        );
    }

    function getSigner(CubeData calldata data, bytes calldata signature)
        public
        view
        returns (address)
    {
        return _getSigner(data, signature);
    }

    function getDigest(bytes32 domainSeparator, bytes32 structHash) public pure returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    function getCubeData(
        address _feeRecipient,
        address _mintTo,
        address factoryAddress,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        CUBE.TokenType tokenType,
        uint256 rakeBps,
        uint256 chainId,
        address rewardRecipientAddress
    ) public pure returns (CUBE.CubeData memory) {
        CUBE.TransactionData[] memory transactions = new CUBE.TransactionData[](1);
        transactions[0] = CUBE.TransactionData({
            txHash: "0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002",
            networkChainId: "evm:137"
        });

        CUBE.RewardData memory reward = CUBE.RewardData({
            tokenAddress: tokenAddress,
            chainId: chainId,
            amount: amount,
            tokenId: tokenId,
            tokenType: tokenType,
            rakeBps: rakeBps,
            factoryAddress: factoryAddress,
            rewardRecipientAddress: rewardRecipientAddress
        });

        CUBE.FeeRecipient[] memory recipients = new CUBE.FeeRecipient[](1);
        recipients[0] = CUBE.FeeRecipient({
            recipient: _feeRecipient,
            BPS: 3300, // 33%
            recipientType: CUBE.FeeRecipientType.LAYER3
        });
        return CUBE.CubeData({
            questId: 1,
            nonce: 1,
            price: 600,
            isNative: true,
            toAddress: _mintTo,
            walletProvider: "MetaMask",
            tokenURI: "ipfs://abc",
            embedOrigin: "test.com",
            transactions: transactions,
            recipients: recipients,
            reward: reward
        });
    }

    function depositNativeToEscrow(address escrow, uint256 amount) public {
        (bool success,) = address(escrow).call{value: amount}("");
        require(success, "native deposit failed");
    }

    function depositERC20ToEscrow(uint256 amount, address to, MockERC20 erc20) public {
        erc20.transfer(to, amount);
    }

    function depositERC721ToEscrow(address from, address to, uint256 tokenId, MockERC721 erc721)
        public
    {
        erc721.safeTransferFrom(from, to, tokenId);
    }

    function processPayouts(CubeData calldata _data) public {
        if (_data.isNative) {
            return _processNativePayouts(_data);
        }
        return _processL3Payouts(_data);
    }
}
