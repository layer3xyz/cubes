// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, Vm, stdError} from "forge-std/Test.sol";

import {DeployEscrow} from "../../script/DeployEscrow.s.sol";
import {Escrow} from "../../src/escrow/Escrow.sol";
import {TaskEscrow} from "../../src/escrow/TaskEscrow.sol";

import {MockERC20} from "../mock/MockERC20.sol";
import {MockERC721} from "../mock/MockERC721.sol";
import {MockERC1155} from "../mock/MockERC1155.sol";
import {ITokenType} from "../../src/escrow/interfaces/ITokenType.sol";

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract TaskEscrowTest is Test {
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

    address public taskEscrowAddr;
    TaskEscrow public taskEscrowMock;
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

        taskEscrowMock = new TaskEscrow(adminAddress, whitelistedTokens, treasury);
        taskEscrowAddr = address(taskEscrowMock);
    }

    ///////////////////////////////////////////////////////////////////////
    //////////////////////////// DEPOSIT //////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    function testDepositNative(uint256 amount) public {
        hoax(adminAddress, amount);
        uint256 preBalEscrow = taskEscrowAddr.balance;
        uint256 preBalAdmin = adminAddress.balance;

        (bool success,) = address(taskEscrowAddr).call{value: amount}("");
        require(success, "native deposit failed");

        uint256 postBalEscrow = taskEscrowAddr.balance;
        uint256 postBalAdmin = adminAddress.balance;

        assertEq(postBalEscrow, preBalEscrow + amount);
        assertEq(postBalAdmin, preBalAdmin - amount);
    }

    function testDepositERC20(uint256 amount) public {
        uint256 preBalance = erc20Mock.balanceOf(taskEscrowAddr);

        uint256 preBalanceAdmin = erc20Mock.balanceOf(adminAddress);
        if (amount > preBalanceAdmin) {
            return;
        }

        vm.startBroadcast(adminAddress);

        erc20Mock.transfer(taskEscrowAddr, amount);
        vm.stopBroadcast();

        uint256 postBalance = erc20Mock.balanceOf(taskEscrowAddr);

        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC721() public {
        uint256 preBalance = erc721Mock.balanceOf(taskEscrowAddr);
        vm.startBroadcast(adminAddress);
        erc721Mock.safeTransferFrom(adminAddress, taskEscrowAddr, 2);
        vm.stopBroadcast();

        uint256 postBalance = erc721Mock.balanceOf(taskEscrowAddr);

        assertEq(postBalance, preBalance + 1);
        assertEq(erc721Mock.ownerOf(2), taskEscrowAddr);
    }

    function testDepositERC1155() public {
        uint256 preBalance = erc1155Mock.balanceOf(taskEscrowAddr, 0);
        vm.startBroadcast(adminAddress);
        erc1155Mock.safeTransferFrom(adminAddress, taskEscrowAddr, 0, 1, "0x00");
        vm.stopBroadcast();

        uint256 postBalance = erc1155Mock.balanceOf(taskEscrowAddr, 0);

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
        taskEscrowMock.withdrawNative(bob, amount, rakeBps);
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
        taskEscrowMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);

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
        taskEscrowMock.withdrawERC721(address(erc721Mock), bob, 2);
        vm.stopBroadcast();

        address postOwnerOf = erc721Mock.ownerOf(2);

        assertEq(preOwnerOf, taskEscrowAddr);
        assertEq(postOwnerOf, bob);
    }

    function testWithdrawERC1155() public {
        testDepositERC1155();

        uint256 preBal = erc1155Mock.balanceOf(bob, 0);

        vm.prank(adminAddress);
        taskEscrowMock.withdrawERC1155(address(erc1155Mock), bob, 1, 0);

        uint256 postBal = erc1155Mock.balanceOf(bob, 0);

        assertEq(preBal, 0);
        assertEq(postBal, 1);
    }

    // TODO[test]: FIXME
    function testWithdrawNotWhitelistedToken() public {
        vm.startBroadcast(adminAddress);

        // create and mint new token
        address token = _createERC20(adminAddress, 1e18);

        // deposit
        uint256 amount = 10;
        MockERC20(token).transfer(taskEscrowAddr, amount);

        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        taskEscrowMock.withdrawERC20(token, bob, amount, 300);

        vm.stopBroadcast();
    }

    function testWithdrawZeroTokenAddress() public {
        vm.prank(adminAddress);
        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        taskEscrowMock.withdrawERC20(address(0), bob, 10, 300);
    }

    function testWithdrawZeroToAddress() public {
        testDepositERC20(10e18);
        vm.prank(adminAddress);
        vm.expectRevert();
        taskEscrowMock.withdrawERC20(address(erc20Mock), address(0), 10, 300);
    }

    function testWithdrawNativeToZeroAddress(uint256 amount) public {
        vm.deal(adminAddress, amount);

        testDepositNative(amount);

        vm.prank(adminAddress);
        vm.expectRevert(Escrow.Escrow__ZeroAddress.selector);
        taskEscrowMock.withdrawNative(address(0), amount, 300);
    }

    // TODO[test]: FIXME
    function testWhitelistToken() public {
        vm.startBroadcast(adminAddress);

        // create and mint new token
        address token = _createERC20(adminAddress, 1e18);

        // deposit
        uint256 amount = 10;
        MockERC20(token).transfer(taskEscrowAddr, amount);

        // it'll revert since token isn't whitelisted
        vm.expectRevert(Escrow.Escrow__TokenNotWhitelisted.selector);
        taskEscrowMock.withdrawERC20(token, bob, amount, 0);

        // whitelist token
        taskEscrowMock.addTokenToWhitelist(token);

        // withdraw to bob
        taskEscrowMock.withdrawERC20(token, bob, amount, 0);
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
        taskEscrowMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
        vm.stopBroadcast();
    }

    function testWithdrawZeroBPS() public {
        testDepositERC20(10e18);

        uint256 amount = 1e18;
        uint256 rakeBps = 0;
        vm.startBroadcast(adminAddress);
        taskEscrowMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
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
        taskEscrowMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
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
        taskEscrowMock.withdrawERC20(address(erc20Mock), bob, amount, rakeBps);
    }

    function testChangeOwner() public {
        address token = makeAddr("someToken");

        bytes4 selector = bytes4(keccak256("OwnableUnauthorizedAccount(address)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, alice);
        vm.expectRevert(expectedError);
        vm.prank(alice);
        taskEscrowMock.addTokenToWhitelist(token);

        address owner = taskEscrowMock.owner();
        assert(owner == adminAddress);

        vm.prank(adminAddress);
        taskEscrowMock.transferOwnership(alice);

        address pendingOwner = taskEscrowMock.pendingOwner();
        assert(pendingOwner == alice);
        address stillOwner = taskEscrowMock.owner();
        assert(stillOwner == adminAddress);

        vm.prank(alice);
        taskEscrowMock.acceptOwnership();
        address newOwner = taskEscrowMock.owner();
        assert(newOwner == alice);

        vm.prank(alice);
        taskEscrowMock.addTokenToWhitelist(token);

        assert(taskEscrowMock.s_whitelistedTokens(token));
    }

    function testRenounceOwnership() public {
        vm.prank(adminAddress);

        // we overwrite this function since there'll never be a case where we want to do this
        taskEscrowMock.renounceOwnership();

        // make sure transfership wasn't renounced
        address owner = taskEscrowMock.owner();
        assert(owner == adminAddress);
    }

    function testEscrowERC165Interface() public view {
        // ERC165 - 0x01ffc9a7
        assertEq(taskEscrowMock.supportsInterface(0x01ffc9a7), true);
    }

    function testERC1155BatchDeposit() public {
        uint256[] memory ids = new uint256[](3);
        uint256[] memory amounts = new uint256[](3);
        address[] memory escrowAddresses = new address[](3);
        uint256 amount = 5;
        for (uint256 i = 0; i < amounts.length; i++) {
            ids[i] = i;
            amounts[i] = amount;
            escrowAddresses[i] = taskEscrowAddr;
            erc1155Mock.mint(adminAddress, 10, i);
        }

        vm.startBroadcast(adminAddress);
        erc1155Mock.safeBatchTransferFrom(adminAddress, taskEscrowAddr, ids, amounts, "0x00");
        vm.stopBroadcast();

        uint256[] memory postBalances = erc1155Mock.balanceOfBatch(escrowAddresses, ids);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(postBalances[i], amount);
        }

        // withdraw
        vm.prank(adminAddress);
        uint256 tokenId = 1;

        taskEscrowMock.withdrawERC1155(address(erc1155Mock), bob, amount, tokenId);

        uint256 escrow1155Balance =
            taskEscrowMock.escrowERC1155Reserves(address(erc1155Mock), tokenId);
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
        IERC721(erc721Mock).transferFrom(adminAddress, taskEscrowAddr, 1);
    }

    function testDepositWithoutData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(alice, amount);
        (bool success,) = taskEscrowAddr.call{value: amount}("");
        assert(success);
        assert(taskEscrowAddr.balance == amount);
    }

    function testDepositWithData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(alice, amount);
        (bool success,) = taskEscrowAddr.call{value: amount}("some data");
        assert(success);
        assert(taskEscrowAddr.balance == amount);
    }

    function depositNativeToEscrow() public {
        hoax(adminAddress, 50 ether);
        (bool success,) = payable(taskEscrowAddr).call{value: 10 ether}("");
        assert(success);
    }

    function testClaimReward() public {
        testDepositERC20(10e18);

        uint256 claimFee = 0.1 ether;
        uint256 reward = 100;

        TaskEscrow.ClaimData memory _data = TaskEscrow.ClaimData({
            taskId: 123,
            token: address(erc20Mock),
            to: bob,
            tokenType: ITokenType.TokenType.ERC20,
            amount: reward,
            tokenId: 0,
            rakeBps: 300,
            claimFee: claimFee,
            nonce: 0,
            txHash: "0xaeacb8a0936dc1a06f0b22223249a4638f5f21130a689bed6a865491d3b6b034",
            networkChainId: "evm:1"
        });

        bytes32 structHash = getStructHash(_data);
        bytes32 digest = getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.deal(bob, claimFee);
        vm.startPrank(bob);
        uint256 preBalance = bob.balance;
        uint256 preERC20Balance = erc20Mock.balanceOf(bob);

        taskEscrowMock.claimReward{value: claimFee}(_data, signature);

        uint256 erc20Amount = erc20Mock.balanceOf(bob);
        uint256 postBalance = bob.balance;
        uint256 rakeFee = reward * 300 / MAX_BPS;

        vm.stopPrank();

        assert(erc20Amount == preERC20Balance + (reward - rakeFee));
        assert(postBalance == preBalance - claimFee);
        assert(treasury.balance == claimFee);

        uint256 contractERC20Balance = erc20Mock.balanceOf(taskEscrowAddr);

        address withdrawalAddr = makeAddr("withdrawal");
        vm.prank(adminAddress);
        taskEscrowMock.withdrawERC20(address(erc20Mock), withdrawalAddr, contractERC20Balance, 0);

        assert(erc20Mock.balanceOf(withdrawalAddr) == contractERC20Balance);
    }

    function getStructHash(TaskEscrow.ClaimData memory data) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "ClaimData(uint256 taskId,address token,address to,uint8 tokenType,uint256 amount,uint256 tokenId,uint256 rakeBps,uint256 claimFee,uint256 nonce,string txHash,string networkChainId)"
                ),
                data.taskId,
                data.token,
                data.to,
                data.tokenType,
                data.amount,
                data.tokenId,
                data.rakeBps,
                data.claimFee,
                data.nonce,
                keccak256(bytes(data.txHash)),
                keccak256(bytes(data.networkChainId))
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
                taskEscrowAddr
            )
        );
    }

    function getDigest(bytes32 domainSeparator, bytes32 structHash) public pure returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }
}
