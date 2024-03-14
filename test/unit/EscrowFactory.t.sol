// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {DeployEscrow} from "../../script/DeployEscrow.s.sol";
import {CUBE} from "../../src/CUBE.sol";
import {CubeV2} from "../contracts/CubeV2.sol";

import {MockERC20} from "../mock/MockERC20.sol";
import {MockERC721} from "../mock/MockERC721.sol";
import {MockERC1155} from "../mock/MockERC1155.sol";
import {Test, console, Vm} from "forge-std/Test.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

import {Escrow} from "../../src/escrow/Escrow.sol";
import {Factory} from "../../src/escrow/Factory.sol";
import {ITokenType} from "../../src/escrow/interfaces/ITokenType.sol";

contract EscrowFactoryTest is Test {
    DeployEscrow public deployer;
    Factory public factoryContract;

    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    uint256 internal ownerPrivateKey;
    address internal ownerPubKey;

    address internal realAccount;
    uint256 internal realPrivateKey;

    // Test Users
    address public adminAddress;
    address public ADMIN = makeAddr("admin");
    uint256 internal adminPrivateKey;
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");

    address public notAdminAddress;
    uint256 internal notAdminPrivKey;

    address public proxyAddress;
    DeployProxy public proxyDeployer;
    CUBE public cubeContract;

    address public factoryAddr;
    address public escrowAddr;
    Escrow public escrowMock;
    MockERC20 public erc20Mock;
    MockERC721 public erc721Mock;
    MockERC1155 public erc1155Mock;

    address[] public whitelistedTokens;

    address public treasury;

    event EscrowRegistered(
        address indexed registror, address indexed escrowAddress, uint256 indexed questId
    );

    function setUp() public {
        ownerPrivateKey = 0xA11CE;
        ownerPubKey = vm.addr(ownerPrivateKey);

        adminPrivateKey = 0x01;
        adminAddress = vm.addr(adminPrivateKey);

        notAdminPrivKey = 0x099;
        notAdminAddress = vm.addr(notAdminPrivKey);

        treasury = makeAddr("treasury");

        proxyDeployer = new DeployProxy();
        proxyAddress = proxyDeployer.deployProxy(ownerPubKey);
        cubeContract = CUBE(payable(proxyAddress));

        vm.startBroadcast(ownerPubKey);
        cubeContract.grantRole(cubeContract.SIGNER_ROLE(), adminAddress);
        vm.stopBroadcast();

        // deploy all necessary contracts and set up dependencies
        deployer = new DeployEscrow();
        (,, address _erc20Mock, address _erc721Mock, address _erc1155Mock) =
            deployer.run(adminAddress, treasury, proxyAddress);

        whitelistedTokens.push(address(_erc20Mock));
        whitelistedTokens.push(address(_erc721Mock));
        whitelistedTokens.push(address(_erc1155Mock));

        factoryAddr = deployer.deployFactory(adminAddress, proxyAddress);
        factoryContract = Factory(payable(factoryAddr));

        bool hasRole = factoryContract.hasRole(factoryContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        assert(hasRole);

        uint256 questId = 0;
        vm.startPrank(adminAddress);
        factoryContract.createEscrow(questId, adminAddress, whitelistedTokens, treasury);
        vm.stopPrank();

        escrowAddr = factoryContract.s_escrows(questId);
        escrowMock = Escrow(payable(escrowAddr));

        assert(escrowMock.s_whitelistedTokens(_erc20Mock));

        erc20Mock = MockERC20(_erc20Mock);
        erc721Mock = MockERC721(_erc721Mock);
        erc1155Mock = MockERC1155(_erc1155Mock);
    }

    function createEscrow(uint256 questId) public returns (uint256) {
        string[] memory communities = new string[](1);
        communities[0] = "test";

        string[] memory tags = new string[](1);
        tags[0] = "DeFi";

        vm.startPrank(adminAddress);
        cubeContract.initializeQuest(
            questId, communities, "Test Quest", CUBE.Difficulty.BEGINNER, CUBE.QuestType.QUEST, tags
        );
        factoryContract.createEscrow(questId, adminAddress, whitelistedTokens, treasury);
        vm.stopPrank();

        return questId;
    }

    function testDepositNative(uint256 amount) public {
        hoax(adminAddress, amount);
        uint256 preBalEscrow = escrowAddr.balance;
        uint256 preBalAdmin = adminAddress.balance;

        (bool success,) = address(escrowAddr).call{value: amount}("");
        require(success, "native deposit failed");

        uint256 postBalEscrow = escrowAddr.balance;
        uint256 postBalAdmin = adminAddress.balance;

        assertEq(postBalEscrow, preBalEscrow + amount);
        assertEq(postBalAdmin, preBalAdmin - amount);
    }

    function testDepositERC20(uint256 amount) public {
        uint256 preBalance = erc20Mock.balanceOf(escrowAddr);

        uint256 preBalanceAdmin = erc20Mock.balanceOf(adminAddress);
        if (amount > preBalanceAdmin) {
            return;
        }

        vm.startBroadcast(adminAddress);

        erc20Mock.transfer(escrowAddr, amount);
        vm.stopBroadcast();

        uint256 postBalance = erc20Mock.balanceOf(escrowAddr);

        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC721() public {
        uint256 preBalance = erc721Mock.balanceOf(escrowAddr);
        vm.startBroadcast(adminAddress);
        erc721Mock.safeTransferFrom(adminAddress, escrowAddr, 2);
        vm.stopBroadcast();

        uint256 postBalance = erc721Mock.balanceOf(escrowAddr);

        assertEq(postBalance, preBalance + 1);
        assertEq(erc721Mock.ownerOf(2), escrowAddr);
    }

    function testDepositERC1155() public {
        uint256 preBalance = erc1155Mock.balanceOf(escrowAddr, 0);
        vm.startBroadcast(adminAddress);
        erc1155Mock.safeTransferFrom(adminAddress, escrowAddr, 0, 1, "0x00");
        vm.stopBroadcast();

        uint256 postBalance = erc1155Mock.balanceOf(escrowAddr, 0);

        assertEq(postBalance, preBalance + 1);
    }

    function testCreateEscrow(uint256 questId, uint256 amount) public {
        questId = bound(questId, 1, type(uint256).max); // 0 is already used in setUp()
        vm.prank(adminAddress);
        factoryContract.createEscrow(questId, adminAddress, whitelistedTokens, treasury);
        address newEscrow = factoryContract.s_escrows(questId);

        MockERC20 erc20 = new MockERC20();
        erc20.mint(newEscrow, amount);

        assertEq(Escrow(payable(newEscrow)).escrowERC20Reserves(address(erc20)), amount);
    }

    // test withdrawal
    function testNativeWithdrawalByAdmin(uint256 questId, uint256 nativeAmount) public {
        questId = bound(questId, 1, type(uint256).max); // 0 is already used in setUp()
        createEscrow(questId);

        nativeAmount = bound(nativeAmount, 0, type(uint256).max);
        testDepositNative(nativeAmount);

        address questEscrow = factoryContract.s_escrows(questId);
        hoax(BOB, nativeAmount);
        (bool success,) = address(questEscrow).call{value: nativeAmount}("");
        assert(success);

        uint256 balNative = questEscrow.balance;
        assertEq(balNative, nativeAmount);

        vm.startPrank(adminAddress);
        cubeContract.unpublishQuest(questId);
        factoryContract.withdrawFunds(questId, ALICE, address(0), 0, ITokenType.TokenType.NATIVE);
        vm.stopPrank();

        assertEq(questEscrow.balance, 0);
        assertEq(ALICE.balance, nativeAmount);
    }

    function testErc20WithdrawalByAdmin(uint256 erc20Amount) public {
        erc20Amount = bound(erc20Amount, 0, type(uint64).max);
        erc20Mock.mint(escrowAddr, erc20Amount);

        uint256 preBalEscrow = erc20Mock.balanceOf(escrowAddr);
        uint256 balErc20 = escrowMock.escrowERC20Reserves(address(erc20Mock));

        assertEq(preBalEscrow, balErc20);

        vm.prank(adminAddress);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);

        uint256 postBalAlice = erc20Mock.balanceOf(ALICE);

        assert(erc20Mock.balanceOf(escrowAddr) == 0);
        assert(escrowMock.escrowERC20Reserves(address(erc20Mock)) == 0);
        assert(postBalAlice == erc20Amount);
    }

    // expect revert
    function testErc20WithdrawalByNonAdmin(uint256 erc20Amount) public {
        erc20Amount = bound(erc20Amount, 0, type(uint64).max);
        erc20Mock.mint(escrowAddr, erc20Amount);

        vm.prank(ALICE);
        vm.expectRevert(Factory.Factory__OnlyCallableByAdmin.selector);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);
    }

    function testUpdateAdmin(uint256 erc20Amount) public {
        erc20Amount = bound(erc20Amount, 0, type(uint64).max);
        erc20Mock.mint(escrowAddr, erc20Amount);

        vm.prank(ALICE);
        vm.expectRevert(Factory.Factory__OnlyCallableByAdmin.selector);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);

        vm.prank(adminAddress);
        factoryContract.updateEscrowAdmin(0, ALICE);

        vm.prank(ALICE);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);

        assert(erc20Mock.balanceOf(ALICE) == erc20Amount);
    }

    function testChangeEscrowAdminAndWhitelistToken() public {
        vm.prank(ALICE);
        address tokenToAdd = makeAddr("tokenToAdd");

        vm.expectRevert(Factory.Factory__OnlyCallableByAdmin.selector);
        factoryContract.addTokenToWhitelist(0, tokenToAdd);

        vm.prank(adminAddress);
        factoryContract.updateEscrowAdmin(0, ALICE);

        vm.prank(ALICE);
        factoryContract.addTokenToWhitelist(0, tokenToAdd);

        bool isWhitelisted = escrowMock.s_whitelistedTokens(tokenToAdd);
        assert(isWhitelisted);
    }

    function testRemoveTokenFromWhitelist() public {
        bool isWhitelisted = escrowMock.s_whitelistedTokens(address(erc20Mock));
        assert(isWhitelisted);

        vm.prank(adminAddress);
        factoryContract.removeTokenFromWhitelist(0, address(erc20Mock));

        bool isWhitelistedPostRemoval = escrowMock.s_whitelistedTokens(address(erc20Mock));
        assert(!isWhitelistedPostRemoval);
    }

    function testUpdateAdminWithdrawByDefaultAdmin(uint256 erc20Amount) public {
        erc20Amount = bound(erc20Amount, 0, type(uint64).max);
        erc20Mock.mint(escrowAddr, erc20Amount);

        vm.prank(ALICE);
        vm.expectRevert(Factory.Factory__OnlyCallableByAdmin.selector);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);

        // update admin but withdraw by default admin, which should still work
        vm.startPrank(adminAddress);
        factoryContract.updateEscrowAdmin(0, ALICE);
        factoryContract.withdrawFunds(0, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);
        vm.stopPrank();

        assert(erc20Mock.balanceOf(ALICE) == erc20Amount);
    }

    function testUpdateAdminByNonAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(Factory.Factory__OnlyCallableByAdmin.selector);
        factoryContract.updateEscrowAdmin(0, ALICE);
    }

    function testCreateEscrowByNonAdmin() public {
        vm.startBroadcast(ALICE);
        bytes4 selector = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        bytes memory expectedError =
            abi.encodeWithSelector(selector, ALICE, factoryContract.DEFAULT_ADMIN_ROLE());
        vm.expectRevert(expectedError);
        factoryContract.createEscrow(2, ALICE, whitelistedTokens, treasury);
        vm.stopBroadcast();
    }

    function testCreateDoubleEscrow(uint256 questId) public {
        questId = bound(questId, 1, type(uint256).max); // 0 is already used in setUp()
        vm.startPrank(adminAddress);
        factoryContract.createEscrow(questId, adminAddress, whitelistedTokens, treasury);
        vm.expectRevert(Factory.Factory__EscrowAlreadyExists.selector);
        factoryContract.createEscrow(questId, adminAddress, whitelistedTokens, treasury);
        vm.stopPrank();
    }

    function testDistributeRewardsNotCUBE() public {
        uint256 questId = 0;
        vm.startPrank(adminAddress);
        erc20Mock.mint(escrowAddr, 1e18);
        vm.expectRevert(Factory.Factory__OnlyCallableByCUBE.selector);
        factoryContract.distributeRewards(
            questId, address(erc20Mock), BOB, 1e18, 0, ITokenType.TokenType.ERC20, 300
        );
        vm.stopPrank();
    }

    function testRotateAdmin() public {
        bool isAdmin = factoryContract.hasRole(factoryContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        assertEq(isAdmin, true);

        vm.startPrank(adminAddress);
        factoryContract.grantRole(factoryContract.DEFAULT_ADMIN_ROLE(), ALICE);

        bool isAdminAlice = factoryContract.hasRole(factoryContract.DEFAULT_ADMIN_ROLE(), ALICE);
        assertEq(isAdminAlice, true);

        factoryContract.renounceRole(factoryContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        bool isAdminPostRenounce =
            factoryContract.hasRole(factoryContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        assertEq(isAdminPostRenounce, false);
        vm.stopPrank();
    }

    function testDepositERC721ToFactory() public {
        vm.prank(adminAddress);
        bytes4 selector = bytes4(keccak256("ERC721InvalidReceiver(address)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, factoryAddr);
        vm.expectRevert(expectedError);
        IERC721(erc721Mock).safeTransferFrom(adminAddress, factoryAddr, 1);
    }

    function testDepositERC1155ToFactory() public {
        vm.prank(adminAddress);
        bytes4 selector = bytes4(keccak256("ERC1155InvalidReceiver(address)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, factoryAddr);
        vm.expectRevert(expectedError);
        ERC1155(erc1155Mock).safeTransferFrom(adminAddress, factoryAddr, 0, 1, "0x00");
    }

    function testDepositToFactoryWithoutData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(ALICE, amount);
        (bool success,) = factoryAddr.call{value: amount}("");
        assert(!success);
    }

    function testDepositToFactoryWithData(uint256 amount) public {
        amount = bound(amount, 0, type(uint256).max);
        hoax(ALICE, amount);
        (bool success,) = factoryAddr.call{value: amount}("some data");
        assert(!success);
    }

    function testUpgrade() public {
        uint256 newValue = 2;
        vm.startPrank(adminAddress);
        Upgrades.upgradeProxy(
            factoryAddr, "CubeV2.sol", abi.encodeCall(CubeV2.initializeV2, (newValue))
        );
        CubeV2 cubeV2 = CubeV2(factoryAddr);
        uint256 value = cubeV2.newValueV2();
        assertEq(value, newValue);
        vm.stopPrank();
    }
}
