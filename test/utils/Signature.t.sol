// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SigUtils {
    bytes32 internal immutable i_domain;
    bytes32 internal immutable i_version;

    constructor(string memory _domain, string memory _version) {
        i_domain = keccak256(bytes(_domain));
        i_version = keccak256(bytes(_version));
    }

    bytes32 internal constant STEP_COMPLETION_HASH =
        keccak256("StepCompletionData(bytes32 stepTxHash,uint256 stepChainId)");
    bytes32 internal constant CUBE_DATA_HASH = keccak256(
        "CubeData(uint256 questId,uint256 userId,uint256 completedAt,uint256 nonce,string walletProvider,string tokenURI,string embedOrigin,address toAddress,StepCompletionData[] steps)StepCompletionData(bytes32 stepTxHash,uint256 stepChainId)"
    );
    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    struct CubeData {
        uint256 questId;
        uint256 userId;
        uint256 completedAt;
        uint256 nonce;
        string walletProvider;
        string tokenURI;
        string embedOrigin;
        address toAddress;
        StepCompletionData[] steps;
    }

    struct StepCompletionData {
        bytes32 stepTxHash;
        uint256 stepChainId;
    }

    function getStructHash(CubeData calldata data) internal view returns (bytes32) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CUBE_DATA_HASH,
                    data.questId,
                    data.userId,
                    data.completedAt,
                    data.nonce,
                    keccak256(bytes(data.walletProvider)),
                    keccak256(bytes(data.tokenURI)),
                    keccak256(bytes(data.embedOrigin)),
                    data.toAddress,
                    _encodeCompletedSteps(data.steps)
                )
            )
        );

        return digest;
    }

    function _encodeStep(StepCompletionData calldata step) internal pure returns (bytes memory) {
        return abi.encode(STEP_COMPLETION_HASH, step.stepTxHash, step.stepChainId);
    }

    function _encodeCompletedSteps(StepCompletionData[] calldata steps)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory encodedSteps = new bytes32[](steps.length);

        // hash each step
        for (uint256 i = 0; i < steps.length; i++) {
            encodedSteps[i] = keccak256(_encodeStep(steps[i]));
        }

        // return hash of the concatenated steps
        return keccak256(abi.encodePacked(encodedSteps));
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
