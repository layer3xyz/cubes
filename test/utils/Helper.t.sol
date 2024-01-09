// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CUBE} from "../../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/Test.sol";

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

    function getTestCubeData(address _feeRecipient, address _mintTo)
        public
        pure
        returns (CUBE.CubeData memory)
    {
        CUBE.TransactionData[] memory transactions = new CUBE.TransactionData[](1);
        transactions[0] = CUBE.TransactionData({
            txHash: "0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002",
            networkChainId: "evm:137"
        });

        CUBE.RewardData memory reward = CUBE.RewardData({
            tokenAddress: address(0),
            chainId: 137,
            amount: 5,
            tokenId: 0,
            tokenType: CUBE.TokenType.NATIVE
        });

        CUBE.FeeRecipient[] memory recipients = new CUBE.FeeRecipient[](1);
        recipients[0] = CUBE.FeeRecipient({recipient: _feeRecipient, BPS: 3300}); // 33%
        return CUBE.CubeData({
            questId: 1,
            nonce: 1,
            price: 10 ether,
            toAddress: _mintTo,
            walletProvider: "MetaMask",
            tokenURI: "ipfs://abc",
            embedOrigin: "test.com",
            transactions: transactions,
            recipients: recipients,
            reward: reward
        });
    }

    function processPayouts(CubeData calldata _data) public {
        return _processPayouts(_data);
    }
}
