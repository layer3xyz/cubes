// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CubeV1} from "./CubeV1.sol";

contract CubeV2 is CubeV1 {
    uint256 public newValueV2;

    function migrateV2(uint256 _newVal) public {
        newValueV2 = _newVal;
    }
}
