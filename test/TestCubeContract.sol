// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {DemoCUBE} from "../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract TestCubeContract is DemoCUBE {
    using ECDSA for bytes32;

    event LogSigner(address signer);

    bytes32 internal constant TEST_HASH = keccak256("CubeData(uint256 questId)");

    constructor() DemoCUBE("Test", "TST", "LAYER3", "1") {}

    function mintCube(CubeData calldata cubeInput, bytes calldata signature) external {
        address signer = getSigner(cubeInput, signature);
        emit LogSigner(signer);
        super._mintCube(cubeInput, signature);
    }

    function getSigner(CubeData calldata _data, bytes calldata signature)
        public
        view
        returns (address)
    {
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(TEST_HASH, _data.questId)));
        return digest.recover(signature);
    }

    function getStructHash(CubeData memory _data) external view returns (bytes32) {
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(TEST_HASH, _data.questId)));
        return digest;
    }
}
