// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IEscrow {
    function withdrawERC20(address token, address to, uint256 amount, uint256 rakeBps) external;
    function withdrawERC721(address token, address to, uint256 tokenId) external;
    function withdrawERC1155(address token, address to, uint256 amount, uint256 tokenId) external;
    function withdrawNative(address to, uint256 amount, uint256 rakeBps) external;

    function escrowERC20Reserves(address token) external view returns (uint256);
    function escrowERC1155Reserves(address token, uint256 tokenId)
        external
        view
        returns (uint256);

    function addTokenToWhitelist(address token) external;
    function changeOwner(address newOwner) external;
}
