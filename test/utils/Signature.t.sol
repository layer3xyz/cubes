// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CubeV1} from "../../src/CubeV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";

contract SigUtils is CubeV1 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    function getStructHash(CubeData calldata data) public pure returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedTags = _encodeTags(data.tags);
        bytes32 encodedRefs = _encodeReferrals(data.refs);

        return keccak256(
            abi.encode(
                CUBE_DATA_HASH,
                data.questId,
                data.userId,
                data.completedAt,
                data.nonce,
                data.price,
                keccak256(bytes(data.walletProvider)),
                keccak256(bytes(data.tokenURI)),
                keccak256(bytes(data.embedOrigin)),
                encodedTags,
                data.toAddress,
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
        pure
        returns (CubeV1.CubeData memory)
    {
        string[] memory tags = new string[](1);
        tags[0] = "DeFi";
        CubeV1.TransactionData[] memory transactions = new CubeV1.TransactionData[](1);
        transactions[0] = CubeV1.TransactionData({
            txHash: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002,
            chainId: 137
        });

        CubeV1.ReferralData[] memory refs = new CubeV1.ReferralData[](1);
        refs[0] = CubeV1.ReferralData({
            referrer: _referrer,
            BPS: 500,
            data: 0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002
        });
        return CubeV1.CubeData({
            questId: 1,
            userId: 1,
            completedAt: 6,
            nonce: 1,
            price: 3,
            walletProvider: "MetaMask",
            tokenURI: "ipfs://abc",
            embedOrigin: "test",
            tags: tags,
            toAddress: _mintTo,
            transactions: transactions,
            refs: refs
        });
    }
}
