// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {CUBE} from "./CUBE.sol";

/// @custom:oz-upgrades-from CUBE
contract CubeV2 is CUBE {
    uint256 public newValueV2;

    function initializeV2(uint256 _newVal) external reinitializer(2) {
        newValueV2 = _newVal;
    }
}
