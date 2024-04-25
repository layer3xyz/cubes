// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, Vm, stdError} from "forge-std/Test.sol";

import {DeployEscrow} from "../../script/DeployEscrow.s.sol";
import {Escrow} from "../../src/escrow/Escrow.sol";
import {EscrowPermit} from "../../src/escrow/EscrowPermit.sol";

import {MockERC20} from "../mock/MockERC20.sol";
import {MockERC721} from "../mock/MockERC721.sol";
import {MockERC1155} from "../mock/MockERC1155.sol";
import {ITokenType} from "../../src/escrow/interfaces/ITokenType.sol";

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract EscrowPermitTest is Test {
    using MessageHashUtils for bytes32;

    DeployEscrow public deployer;

    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    uint256 internal ownerPrivateKey;
    address internal ownerPubKey;

    address internal realAccount;
    uint256 internal realPrivateKey;

    uint256 constant MAX_BPS = 10_000;

    // Test Users
    address public adminAddress;
    address public admin;
    uint256 internal adminPrivateKey;
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public treasury = makeAddr("treasury");

    address public notAdminAddress;
    uint256 internal notAdminPrivKey;

    address public escrowPermitAddr;
    EscrowPermit public escrowPermitMock;
    MockERC20 public erc20Mock;
    MockERC721 public erc721Mock;
    MockERC1155 public erc1155Mock;

    address[] public whitelistedTokens;

    function setUp() public {
        ownerPrivateKey = 0xA11CE;
        ownerPubKey = vm.addr(ownerPrivateKey);

        adminPrivateKey = 0x01;
        adminAddress = vm.addr(adminPrivateKey);

        notAdminPrivKey = 0x099;
        notAdminAddress = vm.addr(notAdminPrivKey);

        // deploy all necessary contracts and set up dependencies
        deployer = new DeployEscrow();
        (,, address erc20, address erc721, address erc1155) =
            deployer.run(adminAddress, treasury, address(0));

        // tokens to be whitelisted in escrow
        whitelistedTokens.push(address(erc20));
        whitelistedTokens.push(address(erc721));
        whitelistedTokens.push(address(erc1155));

        vm.broadcast(adminAddress);
        erc20Mock = MockERC20(erc20);
        erc721Mock = MockERC721(erc721);
        erc1155Mock = MockERC1155(erc1155);

        escrowPermitMock = new EscrowPermit(adminAddress, whitelistedTokens, treasury);
        escrowPermitAddr = address(escrowPermitMock);
    }

    ///////////////////////////////////////////////////////////////////////
    //////////////////////////// DEPOSIT //////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function testDepositNative(uint256 amount) public {
        hoax(adminAddress, amount);
        uint256 preBalEscrow = escrowPermitAddr.balance;
        uint256 preBalAdmin = adminAddress.balance;

        (bool success,) = address(escrowPermitAddr).call{value: amount}("");
        require(success, "native deposit failed");

        uint256 postBalEscrow = escrowPermitAddr.balance;
        uint256 postBalAdmin = adminAddress.balance;

        assertEq(postBalEscrow, preBalEscrow + amount);
        assertEq(postBalAdmin, preBalAdmin - amount);
    }

    function testDepositERC20(uint256 amount) public {
        uint256 preBalance = erc20Mock.balanceOf(escrowPermitAddr);

        uint256 preBalanceAdmin = erc20Mock.balanceOf(adminAddress);
        if (amount > preBalanceAdmin) {
            return;
        }

        vm.startBroadcast(adminAddress);

        erc20Mock.transfer(escrowPermitAddr, amount);
        vm.stopBroadcast();

        uint256 postBalance = erc20Mock.balanceOf(escrowPermitAddr);

        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC721() public {
        uint256 preBalance = erc721Mock.balanceOf(escrowPermitAddr);
        vm.startBroadcast(adminAddress);
        erc721Mock.safeTransferFrom(adminAddress, escrowPermitAddr, 2);
        vm.stopBroadcast();

        uint256 postBalance = erc721Mock.balanceOf(escrowPermitAddr);

        assertEq(postBalance, preBalance + 1);
        assertEq(erc721Mock.ownerOf(2), escrowPermitAddr);
    }

    function testDepositERC1155() public {
        uint256 preBalance = erc1155Mock.balanceOf(escrowPermitAddr, 0);
        vm.startBroadcast(adminAddress);
        erc1155Mock.safeTransferFrom(adminAddress, escrowPermitAddr, 0, 1, "0x00");
        vm.stopBroadcast();

        uint256 postBalance = erc1155Mock.balanceOf(escrowPermitAddr, 0);

        assertEq(postBalance, preBalance + 1);
    }

    ///////////////////////////////////////////////////////////////////////
    //////////////////////////// WITHDRAW /////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function testWithdrawNative() public {
        uint256 amount = 10 ether;
        testDepositNative(amount);

        uint256 rakeBps = 300;
        vm.startBroadcast(adminAddress);
        escrowPermitMock.withdrawNative(bob, amount, rakeBps);
        vm.stopBroadcast();

        uint256 postBalTreasury = treasury.balance;
        uint256 postBalBob = bob.balance;

        uint256 rakeFee = amount * rakeBps / MAX_BPS;

        assertEq(postBalBob, amount - rakeFee);
        assertEq(postBalTreasury, rakeFee);
    }

    function testWithdrawERC20() public {
        testDepositERC20(10e18);

        uint256 amount = 1e18;
        uint256 rakeBps = 300;
        vm.prank(adminAddress);
        escrowPermitMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);

        uint256 postBalTreasury = erc20Mock.balanceOf(treasury);
        uint256 postBalBob = erc20Mock.balanceOf(bob);

        uint256 rakeFee = amount * rakeBps / MAX_BPS;
        assertEq(postBalBob, amount - rakeFee);
        assertEq(postBalTreasury, rakeFee);
    }

    function testWithdrawERC721() public {
        testDepositERC721();

        address preOwnerOf = erc721Mock.ownerOf(2);

        vm.startBroadcast(adminAddress);
        escrowPermitMock.withdrawERC721(address(erc721Mock), bob, 2);
        vm.stopBroadcast();

        address postOwnerOf = erc721Mock.ownerOf(2);

        assertEq(preOwnerOf, escrowPermitAddr);
        assertEq(postOwnerOf, bob);
    }

    function testWithdrawERC1155() public {
        testDepositERC1155();

        uint256 preBal = erc1155Mock.balanceOf(bob, 0);

        vm.prank(adminAddress);
        escrowPermitMock.withdrawERC1155(address(erc1155Mock), bob, 1, 0);

        uint256 postBal = erc1155Mock.balanceOf(bob, 0);

        assertEq(preBal, 0);
        assertEq(postBal, 1);
    }

    function testWithdrawNotWhitelistedToken() public {
        vm.startBroadcast(adminAddress);

        // create and mint new token
        address token = _createERC20(adminAddress, 1e18);

        // deposit
        uint256 amount = 10;
        MockERC20(token).transfer(escrowPermitAddr, amount);

        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        escrowPermitMock.withdrawERC20(token, bob, amount, 300);

        vm.stopBroadcast();
    }

    function testWithdrawZeroTokenAddress() public {
        vm.prank(adminAddress);
        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        escrowPermitMock.withdrawERC20(address(0), bob, 10, 300);
    }

    function testWithdrawZeroToAddress() public {
        testDepositERC20(10e18);
        vm.prank(adminAddress);
        vm.expectRevert();
        escrowPermitMock.withdrawERC20(address(erc20Mock), address(0), 10, 300);
    }

    function testWithdrawNativeToZeroAddress(uint256 amount) public {
        vm.deal(adminAddress, amount);

        testDepositNative(amount);

        vm.prank(adminAddress);
        vm.expectRevert(Escrow.Escrow__ZeroAddress.selector);
        escrowPermitMock.withdrawNative(address(0), amount, 300);
    }

    function testWhitelistToken() public {
        vm.startBroadcast(adminAddress);

        // create and mint new token
        address token = _createERC20(adminAddress, 1e18);

        // deposit
        uint256 amount = 10;
        MockERC20(token).transfer(escrowPermitAddr, amount);

        // it'll revert since token isn't whitelisted
        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        escrowPermitMock.withdrawERC20(token, bob, amount, 0);

        // whitelist token
        escrowPermitMock.addTokenToWhitelist(token);

        // withdraw to bob
        escrowPermitMock.withdrawERC20(token, bob, amount, 0);
        vm.stopBroadcast();

        // verify balance
        uint256 balanceBob = MockERC20(token).balanceOf(bob);
        assertEq(amount, balanceBob);
    }

    ///////////////////////////////////////////////////////////////////////
    ////////////////////////// RAKE PAYOUTS ///////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function testWithdrawTooHighBPS() public {
        testDepositERC20(10e18);

        uint256 amount = 1e18;
        uint256 rakeBps = 10_001; // 10k (100% in bps) is max, make it overflow
        vm.startBroadcast(adminAddress);

        vm.expectRevert(Escrow.Escrow__InvalidRakeBps.selector);
        escrowPermitMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
        vm.stopBroadcast();
    }

    function testWithdrawZeroBPS() public {
        testDepositERC20(10e18);

        uint256 amount = 1e18;
        uint256 rakeBps = 0;
        vm.startBroadcast(adminAddress);
        escrowPermitMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
        vm.stopBroadcast();

        uint256 postBalTreasury = erc20Mock.balanceOf(treasury);
        uint256 postBalBob = erc20Mock.balanceOf(bob);

        uint256 rakeFee = amount * rakeBps / MAX_BPS;
        assertEq(postBalBob, amount - rakeFee);
        assertEq(postBalTreasury, 0);
    }

    function testWithdrawHigherThanBalance() public {
        testDepositERC20(1e18);

        uint256 amount = 10e18;
        uint256 rakeBps = 300;
        vm.startBroadcast(adminAddress);

        vm.expectRevert(Escrow.Escrow__InsufficientEscrowBalance.selector);
        escrowPermitMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
        vm.stopBroadcast();
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////// ACCESS CONTROL //////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function testWithdrawNotAdmin() public {
        testDepositERC20(1e18);

        uint256 amount = 100;
        uint256 rakeBps = 300;
        vm.prank(alice);
        bytes4 selector = bytes4(keccak256("OwnableUnauthorizedAccount(address)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, alice);
        vm.expectRevert(expectedError);
        escrowPermitMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
    }

    function testChangeOwner() public {
        address token = makeAddr("someToken");

        bytes4 selector = bytes4(keccak256("OwnableUnauthorizedAccount(address)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, alice);
        vm.expectRevert(expectedError);
        vm.prank(alice);
        escrowPermitMock.addTokenToWhitelist(token);

        address owner = escrowPermitMock.owner();
        assert(owner == adminAddress);

        vm.prank(adminAddress);
        escrowPermitMock.transferOwnership(alice);

        address pendingOwner = escrowPermitMock.pendingOwner();
        assert(pendingOwner == alice);
        address stillOwner = escrowPermitMock.owner();
        assert(stillOwner == adminAddress);

        vm.prank(alice);
        escrowPermitMock.acceptOwnership();
        address newOwner = escrowPermitMock.owner();
        assert(newOwner == alice);

        vm.prank(alice);
        escrowPermitMock.addTokenToWhitelist(token);

        assert(escrowPermitMock.s_whitelistedTokens(token));
    }

    function testRenounceOwnership() public {
        vm.prank(adminAddress);

        // we overwrite this function since there'll never be a case where we want to do this
        escrowPermitMock.renounceOwnership();

        // make sure transfership wasn't renounced
        address owner = escrowPermitMock.owner();
        assert(owner == adminAddress);
    }

    function testEscrowERC165Interface() public {
        // ERC165 - 0x01ffc9a7
        assertEq(escrowPermitMock.supportsInterface(0x01ffc9a7), true);
    }

    function testERC1155BatchDeposit() public {
        uint256[] memory ids = new uint256[](3);
        uint256[] memory amounts = new uint256[](3);
        address[] memory escrowAddresses = new address[](3);
        uint256 amount = 5;
        for (uint256 i = 0; i < amounts.length; i++) {
            ids[i] = i;
            amounts[i] = amount;
            escrowAddresses[i] = escrowPermitAddr;
            erc1155Mock.mint(adminAddress, 10, i);
        }

        vm.startBroadcast(adminAddress);
        erc1155Mock.safeBatchTransferFrom(adminAddress, escrowPermitAddr, ids, amounts, "0x00");
        vm.stopBroadcast();

        uint256[] memory postBalances = erc1155Mock.balanceOfBatch(escrowAddresses, ids);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(postBalances[i], amount);
        }

        // withdraw
        vm.prank(adminAddress);
        uint256 tokenId = 1;

        escrowPermitMock.withdrawERC1155(address(erc1155Mock), bob, amount, tokenId);

        uint256 escrow1155Balance =
            escrowPermitMock.escrowERC1155Reserves(address(erc1155Mock), tokenId);
        assert(escrow1155Balance == 0);
        assert(erc1155Mock.balanceOf(bob, tokenId) == amount);
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////// HELPER FUNCTIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function _createERC20(address _to, uint256 _amount) internal returns (address) {
        address token = address(new MockERC20());
        MockERC20(token).mint(_to, _amount);

        return token;
    }

    function depositERC721ToEscrow() public {
        IERC721(erc721Mock).transferFrom(adminAddress, escrowPermitAddr, 1);
    }

    function testDepositWithoutData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(alice, amount);
        (bool success,) = escrowPermitAddr.call{value: amount}("");
        assert(success);
        assert(escrowPermitAddr.balance == amount);
    }

    function testDepositWithData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(alice, amount);
        (bool success,) = escrowPermitAddr.call{value: amount}("some data");
        assert(success);
        assert(escrowPermitAddr.balance == amount);
    }

    function depositNativeToEscrow() public {
        hoax(adminAddress, 50 ether);
        (bool success,) = payable(escrowPermitAddr).call{value: 10 ether}("");
        assert(success);
    }

    function testClaimReward() public {
        testDepositERC20(10e18);

        uint256 claimFee = 0.1 ether;
        uint256 reward = 100;

        EscrowPermit.ClaimData memory _data = EscrowPermit.ClaimData({
            id: 123,
            source: "test",
            token: address(erc20Mock),
            to: bob,
            amount: reward,
            tokenId: 0,
            tokenType: ITokenType.TokenType.ERC20,
            rakeBps: 300,
            claimFee: claimFee,
            nonce: 0
        });

        bytes32 structHash = getStructHash(_data);
        bytes32 digest = getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.deal(bob, claimFee);
        vm.startPrank(bob);
        uint256 preBalance = bob.balance;
        uint256 preERC20Balance = erc20Mock.balanceOf(bob);

        escrowPermitMock.claimReward{value: claimFee}(_data, signature);

        uint256 erc20Amount = erc20Mock.balanceOf(bob);
        uint256 postBalance = bob.balance;
        uint256 rakeFee = reward * 300 / MAX_BPS;

        vm.stopPrank();

        assert(erc20Amount == preERC20Balance + (reward - rakeFee));
        assert(postBalance == preBalance - claimFee);
        assert(treasury.balance == claimFee);

        uint256 contractERC20Balance = erc20Mock.balanceOf(escrowPermitAddr);

        address withdrawalAddr = makeAddr("withdrawal");
        vm.prank(adminAddress);
        escrowPermitMock.withdrawERC20(address(erc20Mock), withdrawalAddr, contractERC20Balance, 0);

        assert(erc20Mock.balanceOf(withdrawalAddr) == contractERC20Balance);
    }

    function getStructHash(EscrowPermit.ClaimData memory data) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "ClaimData(uint256 id,string source,address token,address to,uint256 amount,uint256 tokenId,uint8 tokenType,uint256 rakeBps,uint256 claimFee,uint256 nonce)"
                ),
                data.id,
                keccak256(bytes(data.source)),
                data.token,
                data.to,
                data.amount,
                data.tokenId,
                data.tokenType,
                data.rakeBps,
                data.claimFee,
                data.nonce
            )
        );
    }

    function getDomainSeparator() internal view virtual returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(SIGNATURE_DOMAIN)),
                keccak256(bytes(SIGNING_VERSION)),
                block.chainid,
                escrowPermitAddr
            )
        );
    }

    function getDigest(bytes32 domainSeparator, bytes32 structHash) public pure returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }
}
