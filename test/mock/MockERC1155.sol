// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

contract MockERC1155 is ERC1155 {
    constructor() ERC1155("Mock1155") {}

    function mint(address to, uint256 amount, uint256 id) public {
        _mint(to, id, amount, "0x00");
    }
}
