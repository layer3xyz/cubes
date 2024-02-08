// SPDX-License-Identifier: Apache-2.0
/*
.____                             ________
|    |   _____  ___.__. __________\_____  \
|    |   \__  \<   |  |/ __ \_  __ \_(__  <
|    |___ / __ \\___  \  ___/|  | \/       \
|_______ (____  / ____|\___  >__| /______  /
        \/    \/\/         \/            \/
*/

pragma solidity 0.8.20;

import {CUBE} from "../../src/CUBE.sol";

/// @title CubeV2
/// @dev Proxy upgrade test contract
/// @custom:oz-upgrades-from CUBE
contract CubeV2 is CUBE {
    uint256 public newValueV2;

    function initializeV2(uint256 _newVal) external reinitializer(2) {
        newValueV2 = _newVal;
    }
}
