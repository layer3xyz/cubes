// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract MockERC721 is ERC721 {
    uint256 internal s_currentTokenId;

    constructor() ERC721("MockToken", "MOCK") {}

    function mint(address to) public {
        unchecked {
            ++s_currentTokenId;
        }
        _mint(to, s_currentTokenId);
    }
}
