// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CubeV1} from "./CubeV1.sol";

/// @custom:oz-upgrades-from CubeV1
contract CubeV2 is CubeV1 {
    uint256 public newValueV2;

    function initializeV2(uint256 _newVal) public reinitializer(2) {
        newValueV2 = _newVal;
    }
}
