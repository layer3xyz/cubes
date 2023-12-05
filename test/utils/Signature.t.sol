// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CUBE} from "../../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";

contract SigUtils is CUBE {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    function getStructHash(CubeData calldata data) public pure returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedRefs = _encodeReferrals(data.refs);

        return keccak256(
            abi.encode(
                CUBE_DATA_HASH,
                data.questId,
                data.userId,
                data.nonce,
                data.price,
                data.completedAt,
                data.toAddress,
                keccak256(bytes(data.walletProvider)),
                keccak256(bytes(data.tokenURI)),
                keccak256(bytes(data.embedOrigin)),
                encodedTxs,
                encodedRefs
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

    function getTestCubeData(address _referrer, address _mintTo)
        public
        view
        returns (CUBE.CubeData memory)
    {
        CUBE.TransactionData[] memory transactions = new CUBE.TransactionData[](1);
        transactions[0] = CUBE.TransactionData({
            txHash: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002,
            chainId: 137
        });

        CUBE.ReferralData[] memory refs = new CUBE.ReferralData[](1);
        refs[0] = CUBE.ReferralData({
            referrer: _referrer,
            BPS: 500,
            data: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002
        });
        return CUBE.CubeData({
            questId: 1,
            userId: 1,
            nonce: 1,
            price: 10 ether,
            completedAt: uint64(block.timestamp),
            toAddress: _mintTo,
            walletProvider: "MetaMask",
            tokenURI: "ipfs://abc",
            embedOrigin: "test",
            transactions: transactions,
            refs: refs
        });
    }
}
