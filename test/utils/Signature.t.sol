// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {CubeV1} from "../../src/CubeV1.sol";

contract SigUtils {
    bytes32 internal immutable i_domain;
    bytes32 internal immutable i_version;

    constructor(string memory _domain, string memory _version) {
        i_domain = keccak256(bytes(_domain));
        i_version = keccak256(bytes(_version));
    }

    bytes32 internal constant TX_DATA_HASH =
        keccak256("TransactionData(bytes32 txHash,uint256 chainId)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 completedAt,uint256 nonce,uint256 price,string walletProvider,string tokenURI,string embedOrigin,string[] tags,address toAddress,TransactionData[] transactions)TransactionData(bytes32 txHash,uint256 chainId)"
    );
    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function getStructHash(CubeV1.CubeData calldata data) external view returns (bytes32) {
        bytes32 encodedTxs = _encodeCompletedTxs(data.transactions);
        bytes32 encodedTags = _encodeTags(data.tags);
        bytes32 digest = _hashTypedDataV4(
            keccak256(
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
                    encodedTxs
                )
            )
        );

        return digest;
    }

    function _encodeTx(CubeV1.TransactionData calldata transaction)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(TX_DATA_HASH, transaction.txHash, transaction.chainId);
    }

    function _encodeCompletedTxs(CubeV1.TransactionData[] calldata txData)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory encodedTxs = new bytes32[](txData.length);
        // hash each tx
        for (uint256 i = 0; i < txData.length;) {
            encodedTxs[i] = keccak256(_encodeTx(txData[i]));
            unchecked {
                ++i;
            }
        }

        // return hash of the concatenated txs
        return keccak256(abi.encodePacked(encodedTxs));
    }

    function _encodeTags(string[] calldata tags) internal pure returns (bytes32) {
        bytes32[] memory encodedTxs = new bytes32[](tags.length);
        for (uint256 i = 0; i < tags.length;) {
            encodedTxs[i] = keccak256(abi.encodePacked(tags[i]));
            unchecked {
                ++i;
            }
        }

        // return hash of the concatenated txs
        return keccak256(abi.encodePacked(encodedTxs));
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, i_domain, i_version, block.chainid, address(this)));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        // toTypedDataHash takes care of the "\x19\x01"
        return MessageHashUtils.toTypedDataHash(_buildDomainSeparator(), structHash);
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
}
