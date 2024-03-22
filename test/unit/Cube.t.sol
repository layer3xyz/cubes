// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console, Vm} from "forge-std/Test.sol";

import {CUBE} from "../../src/CUBE.sol";
import {Factory} from "../../src/escrow/Factory.sol";
import {Escrow} from "../../src/escrow/Escrow.sol";
import {ITokenType} from "../../src/escrow/interfaces/ITokenType.sol";

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {DeployEscrow} from "../../script/DeployEscrow.s.sol";
import {Helper} from "../utils/Helper.t.sol";

import {MockERC20} from "../mock/MockERC20.sol";
import {MockERC721} from "../mock/MockERC721.sol";
import {MockERC1155} from "../mock/MockERC1155.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /* EVENTS */
    event QuestMetadata(
        uint256 indexed questId,
        CUBE.QuestType questType,
        CUBE.Difficulty difficulty,
        string title,
        string[] tags,
        string[] communities
    );
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        address indexed claimer,
        uint256 issueNumber,
        string walletProvider,
        string embedOrigin
    );
    event CubeTransaction(uint256 indexed cubeTokenId, string txHash, string networkChainId);

    event TokenReward(
        uint256 indexed cubeTokenId,
        address indexed tokenAddress,
        uint256 indexed chainId,
        uint256 amount,
        uint256 tokenId,
        ITokenType.TokenType tokenType
    );

    DeployProxy public deployer;
    CUBE public cubeContract;

    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    Helper internal helper;

    uint256 internal ownerPrivateKey;
    address internal ownerPubKey;

    address internal realAccount;
    uint256 internal realPrivateKey;

    DeployEscrow public deployEscrow;
    Factory public factoryContract;
    Escrow public mockEscrow;
    MockERC20 public erc20Mock;
    MockERC721 public erc721Mock;
    MockERC1155 public erc1155Mock;

    // Test Users
    address public adminAddress;
    address public ADMIN = makeAddr("admin");
    uint256 internal adminPrivateKey;
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");
    address public TREASURY = makeAddr("treasury");

    address public notAdminAddress;
    uint256 internal notAdminPrivKey;

    address public proxyAddress;

    function getDomainSeparator() internal view virtual returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(SIGNATURE_DOMAIN)),
                keccak256(bytes(SIGNING_VERSION)),
                block.chainid,
                proxyAddress
            )
        );
    }

    function setUp() public {
        ownerPrivateKey = 0xA11CE;
        ownerPubKey = vm.addr(ownerPrivateKey);

        adminPrivateKey = 0x01;
        adminAddress = vm.addr(adminPrivateKey);

        notAdminPrivKey = 0x099;
        notAdminAddress = vm.addr(notAdminPrivKey);

        deployer = new DeployProxy();
        proxyAddress = deployer.deployProxy(ownerPubKey);
        cubeContract = CUBE(payable(proxyAddress));

        vm.startBroadcast(ownerPubKey);
        cubeContract.grantRole(cubeContract.SIGNER_ROLE(), adminAddress);
        vm.stopBroadcast();

        deployEscrow = new DeployEscrow();
        (
            address factory,
            address escrow,
            address erc20Addr,
            address erc721Addr,
            address erc1155Addr
        ) = deployEscrow.run(adminAddress, TREASURY, proxyAddress);

        mockEscrow = Escrow(payable(escrow));
        erc20Mock = MockERC20(erc20Addr);
        erc721Mock = MockERC721(erc721Addr);
        erc1155Mock = MockERC1155(erc1155Addr);

        factoryContract = Factory(factory);

        vm.startPrank(adminAddress);
        cubeContract.initializeQuest(
            deployEscrow.QUEST_ID(),
            new string[](0),
            "Quest Title",
            CUBE.Difficulty.BEGINNER,
            CUBE.QuestType.QUEST,
            new string[](0)
        );

        vm.deal(adminAddress, 100 ether);
        fundEscrowContract();

        helper = new Helper();

        // contract warm up
        _mintCube();

        // withdraw in order for contract to start at 0 balance
        vm.prank(ownerPubKey);
        cubeContract.withdraw();
    }

    function _mintCube() internal {
        CUBE.CubeData memory _data = helper.getCubeData({
            _feeRecipient: makeAddr("feeRecipient"),
            _mintTo: makeAddr("mintTo"),
            factoryAddress: address(factoryContract),
            tokenAddress: address(erc20Mock),
            tokenId: 0,
            tokenType: ITokenType.TokenType.ERC20,
            rakeBps: 0,
            amount: 10,
            chainId: 137
        });
        _data.nonce = 0;

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function fundEscrowContract() internal {
        // native
        uint256 amount = 100 ether;
        (bool success,) = address(mockEscrow).call{value: amount}("");
        require(success, "native deposit failed");

        // erc721
        erc721Mock.safeTransferFrom(adminAddress, address(mockEscrow), 2);

        // erc20
        uint256 erc20Amount = 10e18;
        erc20Mock.mint(address(mockEscrow), erc20Amount);

        // erc1155
        erc1155Mock.mint(address(mockEscrow), 1e18, 0);
        erc1155Mock.mint(address(adminAddress), 1e18, 0);
    }

    function testWithdrawFundsWhenQuestInactive() public {
        vm.startPrank(adminAddress);

        erc20Mock.transfer(address(mockEscrow), 100);

        // withdrawal should revert if quest is still active
        bool isQuestActive = cubeContract.isQuestActive(1);
        assert(isQuestActive == true);

        vm.expectRevert(Factory.Factory__CUBEQuestIsActive.selector);
        factoryContract.withdrawFunds(1, ALICE, address(erc20Mock), 0, ITokenType.TokenType.ERC20);

        uint256 escrowBalanceBefore = erc20Mock.balanceOf(address(mockEscrow));

        cubeContract.unpublishQuest(1);
        bool isQuestActive2 = cubeContract.isQuestActive(1);
        assert(isQuestActive2 == false);

        factoryContract.withdrawFunds(1, BOB, address(erc20Mock), 0, ITokenType.TokenType.ERC20);
        vm.stopPrank();

        assert(erc20Mock.balanceOf(BOB) == escrowBalanceBefore);
    }

    function testInitializeQuest() public {
        uint256 questId = 1;
        string[] memory communities = new string[](2);
        communities[0] = "Community1";
        communities[1] = "Community2";
        string memory title = "Quest Title";
        CUBE.Difficulty difficulty = CUBE.Difficulty.BEGINNER;
        CUBE.QuestType questType = CUBE.QuestType.QUEST;
        string[] memory tags = new string[](1);
        tags[0] = "DeFi";

        // Expecting QuestMetadata events to be emitted
        vm.expectEmit(true, true, false, true);
        emit QuestMetadata(questId, questType, difficulty, title, tags, communities);

        vm.prank(adminAddress);
        cubeContract.initializeQuest(questId, communities, title, difficulty, questType, tags);
    }

    function testInitializeQuestNotAsSigner() public {
        uint256 questId = 1;
        string[] memory communities = new string[](2);

        communities[0] = "Community1";
        communities[1] = "Community2";
        string memory title = "Quest Title";
        CUBE.Difficulty difficulty = CUBE.Difficulty.BEGINNER;
        CUBE.QuestType questType = CUBE.QuestType.QUEST;

        string[] memory tags = new string[](1);
        tags[0] = "DeFi";

        bytes4 selector = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        bytes memory expectedError = abi.encodeWithSelector(selector, ALICE, keccak256("SIGNER"));
        vm.expectRevert(expectedError);
        vm.prank(ALICE);
        cubeContract.initializeQuest(questId, communities, title, difficulty, questType, tags);
    }

    function testMintCubeNativeReward() public {
        uint256 rake = 300;
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getCustomSignedCubeMintData(
            address(0), 0, 2 ether, ITokenType.TokenType.NATIVE, rake, 137
        );

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMintCubeNoReward() public {
        uint256 rake = 300;
        uint256 amount = 100;
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getCustomSignedCubeMintData(
            address(erc20Mock), 0, amount, ITokenType.TokenType.ERC20, rake, 0
        );

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 1 ether}(cubeData, signatures);

        uint256 bobBal = erc20Mock.balanceOf(BOB);
        assert(bobBal == 0);
        assert(erc20Mock.balanceOf(TREASURY) == 0);
    }

    function testMintCubeERC20Reward() public {
        uint256 rake = 300; // 3%
        uint256 amount = 100;
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getCustomSignedCubeMintData(
            address(erc20Mock), 0, amount, ITokenType.TokenType.ERC20, rake, 137
        );

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 1 ether}(cubeData, signatures);

        uint256 bobBal = erc20Mock.balanceOf(BOB);
        uint256 rakePayout = (amount * rake) / 10_000;
        assert(bobBal == amount - rakePayout);
        assert(erc20Mock.balanceOf(TREASURY) == rakePayout);
    }

    function testMintCubeERC721Reward() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getCustomSignedCubeMintData(
            address(erc721Mock), 2, 1, ITokenType.TokenType.ERC721, 1, 137
        );

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 1 ether}(cubeData, signatures);

        address ownerOf = erc721Mock.ownerOf(2);
        assertEq(ownerOf, BOB);
    }

    function testMintCubeERC1155Reward() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getCustomSignedCubeMintData(
            address(erc1155Mock), 0, 2, ITokenType.TokenType.ERC1155, 0, 137
        );

        bool isSigner = cubeContract.hasRole(keccak256("SIGNER"), adminAddress);
        assertEq(isSigner, true);

        hoax(adminAddress, 10 ether);

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        assertEq(cubeContract.tokenURI(1), "ipfs://abc");
        assertEq(cubeContract.ownerOf(1), BOB);

        uint256 bobBal = erc1155Mock.balanceOf(address(BOB), 0);
        assertEq(bobBal, 2);
    }

    function testDepositNativeToEscrow() public {
        uint256 preBalance = address(mockEscrow).balance;

        uint256 amount = 100 ether;
        hoax(adminAddress, amount);
        (bool success,) = address(mockEscrow).call{value: amount}("");
        require(success, "native deposit failed");

        uint256 postBalance = address(mockEscrow).balance;
        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC20ToEscrow() public {
        uint256 preBalance = erc20Mock.balanceOf(address(mockEscrow));

        uint256 amount = 100;
        vm.prank(adminAddress);
        erc20Mock.transfer(address(mockEscrow), amount);

        uint256 postBalance = erc20Mock.balanceOf(address(mockEscrow));

        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC1155ToEscrow() public {
        uint256 preBalance = erc1155Mock.balanceOf(address(mockEscrow), 0);

        vm.prank(adminAddress);
        uint256 amount = 100;
        erc1155Mock.safeTransferFrom(address(adminAddress), address(mockEscrow), 0, amount, "0x00");

        uint256 postBalance = erc1155Mock.balanceOf(address(mockEscrow), 0);

        assertEq(postBalance, preBalance + amount);
    }

    function testDepositERC721ToEscrow() public {
        uint256 preBalance = erc721Mock.balanceOf(address(mockEscrow));

        vm.prank(adminAddress);
        erc721Mock.safeTransferFrom(adminAddress, address(mockEscrow), 1);

        uint256 postBalance = erc721Mock.balanceOf(address(mockEscrow));

        assertEq(postBalance, preBalance + 1);
        assertEq(erc721Mock.ownerOf(2), address(mockEscrow));
    }

    function testMintCubes() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        bool isSigner = cubeContract.hasRole(keccak256("SIGNER"), adminAddress);
        assertEq(isSigner, true);

        hoax(adminAddress, 10 ether);

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        assertEq(cubeContract.tokenURI(1), "ipfs://abc");
        assertEq(cubeContract.ownerOf(1), BOB);
    }

    function testMintCubesRewardEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting TokenReward event to be emitted
        vm.expectEmit(true, true, true, true);
        emit TokenReward(1, address(erc20Mock), 137, 100, 0, ITokenType.TokenType.ERC20);

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMintCubesTxEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting CubeTransaction event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CubeTransaction(
            1, "0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002", "evm:137"
        );

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMintCubesClaimEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting TokenReward events to be emitted
        vm.expectEmit(true, true, true, true);
        emit CubeClaim(1, 1, BOB, 2, "MetaMask", "test.com");

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testNonceReuse() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        CUBE.CubeData memory data2 = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.nonce = 1;
        data2.nonce = 1;

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = helper.getStructHash(data2);
        bytes32 digest2 = helper.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(adminPrivateKey, digest2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature2;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        vm.expectRevert(CUBE.CUBE__NonceAlreadyUsed.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testCubeMintDifferentSigners() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        CUBE.CubeData memory data2 = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        data.nonce = 1;
        data2.nonce = 2;

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = helper.getStructHash(data2);
        bytes32 digest2 = helper.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(notAdminPrivKey, digest2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature2;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        vm.expectRevert(CUBE.CUBE__IsNotSigner.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testMultipleCubeDataMint() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        CUBE.CubeData memory data2 = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data2.nonce = 32142;

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = helper.getStructHash(data2);
        bytes32 digest2 = helper.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(adminPrivateKey, digest2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature2;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
        assertEq(cubeContract.ownerOf(1), BOB);
    }

    function testMismatchCubeDataAndSignatureArray() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        CUBE.CubeData memory data2 = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        vm.expectRevert(CUBE.CUBE__SignatureAndCubesInputMismatch.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testEmptySignatureArray() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        CUBE.CubeData memory data2 = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        // expected error: ECDSAInvalidSignatureLength(0)
        vm.expectRevert();
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testInvalidSignature() public {
        CUBE.CubeData memory _data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        // Sign the digest with a non-signer key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notAdminPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        hoax(adminAddress, 10 ether);

        // Expect the mint to fail due to invalid signature
        vm.expectRevert(CUBE.CUBE__IsNotSigner.selector);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testEmptyCubeDataTxs() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.transactions = new CUBE.TransactionData[](1);

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testEmptyReferrals() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.recipients = new CUBE.FeeRecipient[](1);

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMultipleRefPayouts() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            200,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 4000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        uint256 amount = 0.01 ether;

        hoax(adminAddress, amount);
        cubeContract.mintCubes{value: amount}(cubeData, signatures);

        assertEq(ALICE.balance, amount * 500 / 10_000); // 5%
        assertEq(BOB.balance, amount * 4000 / 10_000); // 40%
        assertEq(adminAddress.balance, amount * 4000 / 10_000); // 40%
    }

    function testExceedContractBalance() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            10 ether,
            ITokenType.TokenType.NATIVE,
            0,
            137
        );
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 8000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 8000});

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        vm.expectRevert(CUBE.CUBE__ExcessiveFeePayout.selector);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        // alice's balance should be 0 since contract tx reverted
        assertEq(ALICE.balance, 0);
    }

    function testTooHighReferrerBPS() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({
            recipient: BOB,
            BPS: 10_001 // max is 10k
        });
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        vm.expectRevert(CUBE.CUBE__BPSTooHigh.selector);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testTooHighReferralAmount() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 9000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        vm.expectRevert(CUBE.CUBE__ExcessiveFeePayout.selector);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
        assertEq(ALICE.balance, 0);
    }

    function testReuseSignature() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature;
        cubeData[0] = data;
        cubeData[1] = data;

        hoax(adminAddress, 20 ether);
        vm.expectRevert(CUBE.CUBE__NonceAlreadyUsed.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testModifyNonceAfterSignature() public {
        CUBE.CubeData memory data = helper.getCubeData(
            ALICE,
            BOB,
            address(factoryContract),
            address(erc20Mock),
            0,
            100,
            ITokenType.TokenType.ERC20,
            0,
            137
        );

        bytes32 structHash = helper.getStructHash(data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature;
        cubeData[0] = data;

        // modify nonce
        CUBE.CubeData memory modData = data;
        modData.nonce = 324234;
        cubeData[1] = modData;

        hoax(adminAddress, 20 ether);

        // expect CUBE__IsNotSigner since we changed the data (nonce)
        // and we should not be able to recover the signer address
        vm.expectRevert(CUBE.CUBE__IsNotSigner.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testMultipleReferrers() public {
        CUBE.CubeData[] memory _data = _getCubeMintData();

        uint256 preOwnerBalance = ownerPubKey.balance;

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);

        _data[0].recipients = new CUBE.FeeRecipient[](3);
        _data[0].recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        _data[0].recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 800});
        _data[0].recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 1000});

        bytes32 structHash = helper.getStructHash(_data[0]);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        cubeData[0] = _data[0];
        signatures[0] = signature;

        uint256 amount = 0.01 ether;

        hoax(adminAddress, amount);
        cubeContract.mintCubes{value: amount}(cubeData, signatures);

        uint256 expectedBalAlice = amount * 500 / 10_000;
        assertEq(ALICE.balance, expectedBalAlice);
        uint256 expectedBalBob = amount * 800 / 10_000;
        assertEq(BOB.balance, expectedBalBob);
        uint256 expectedBalAdmin = amount * 1000 / 10_000;
        assertEq(adminAddress.balance, expectedBalAdmin);
        // 23% taken by referrers, so 77% should be left
        uint256 expectedMintProfit = amount * 7700 / 10_000;
        assertEq(proxyAddress.balance, expectedMintProfit);

        vm.prank(ownerPubKey);
        cubeContract.withdraw();

        assertEq(ownerPubKey.balance - preOwnerBalance, expectedMintProfit);
        assertEq(proxyAddress.balance, 0);
    }

    function testReferralFees() public {
        uint256 preContractBalance = proxyAddress.balance;
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        uint256 amount = 0.01 ether;

        // send from admin
        hoax(adminAddress, amount);
        cubeContract.mintCubes{value: amount}(cubeData, signatures);

        uint256 balanceAlice = ALICE.balance;
        uint256 balanceContract = proxyAddress.balance;

        uint256 expectedBal = preContractBalance + (amount * 3300 / 10_000);

        assertEq(balanceAlice, expectedBal);
        assertEq(balanceContract, (amount - expectedBal) + preContractBalance);
    }

    function testUnpublishQuest(uint256 questId) public {
        vm.startPrank(adminAddress);
        cubeContract.initializeQuest(
            questId,
            new string[](0),
            "",
            CUBE.Difficulty.BEGINNER,
            CUBE.QuestType.QUEST,
            new string[](0)
        );
        bool isActive = cubeContract.isQuestActive(questId);
        assertEq(isActive, true);

        cubeContract.unpublishQuest(questId);

        vm.stopPrank();
        bool isActive2 = cubeContract.isQuestActive(questId);
        assert(isActive2 == false);
    }

    function testInitalizeQuestEvent() public {
        uint256 questId = 123;
        string[] memory communities = new string[](1);
        communities[0] = "Community1";
        string memory title = "Quest Title";
        string[] memory tags = new string[](1);
        tags[0] = "NFTs";
        CUBE.Difficulty difficulty = CUBE.Difficulty.BEGINNER;
        CUBE.QuestType questType = CUBE.QuestType.QUEST;

        vm.recordLogs();
        emit QuestMetadata(questId, questType, difficulty, title, tags, communities);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 1);
        assertEq(entries[0].topics[1], bytes32(uint256(questId)));
    }

    function testTurnOffMinting() public {
        bool isActive = cubeContract.s_isMintingActive();

        vm.prank(ownerPubKey);
        cubeContract.setIsMintingActive(false);

        bool isActiveUpdated = cubeContract.s_isMintingActive();

        assert(isActiveUpdated != isActive);
    }

    function test721Interface() public view {
        bool supportsInterface = cubeContract.supportsInterface(type(IERC721).interfaceId);
        assert(supportsInterface == true);
    }

    function testRevokeSignerRole() public {
        bytes32 signerRole = keccak256("SIGNER");
        bool isSigner = cubeContract.hasRole(signerRole, adminAddress);
        assertEq(isSigner, true);

        vm.prank(adminAddress);
        cubeContract.renounceRole(signerRole, adminAddress);
    }

    function testRevokeAdminRole() public {
        bool isAdmin = cubeContract.hasRole(cubeContract.DEFAULT_ADMIN_ROLE(), ownerPubKey);
        assertEq(isAdmin, true);

        vm.startPrank(ownerPubKey);
        cubeContract.grantRole(cubeContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        cubeContract.revokeRole(cubeContract.DEFAULT_ADMIN_ROLE(), ownerPubKey);

        bool isAdmin2 = cubeContract.hasRole(cubeContract.DEFAULT_ADMIN_ROLE(), adminAddress);
        assertEq(isAdmin2, true);
        vm.stopPrank();
    }

    function testRotateAdmin() public {
        bool isAdmin = cubeContract.hasRole(cubeContract.DEFAULT_ADMIN_ROLE(), ownerPubKey);
        assertEq(isAdmin, true);

        vm.startPrank(ownerPubKey);
        cubeContract.grantRole(cubeContract.DEFAULT_ADMIN_ROLE(), ALICE);

        bool isAdmin2 = cubeContract.hasRole(cubeContract.DEFAULT_ADMIN_ROLE(), ALICE);
        assertEq(isAdmin2, true);

        cubeContract.renounceRole(cubeContract.DEFAULT_ADMIN_ROLE(), ownerPubKey);
        bool isAdmin3 = cubeContract.hasRole(cubeContract.DEFAULT_ADMIN_ROLE(), ownerPubKey);
        assertEq(isAdmin3, false);
        vm.stopPrank();
    }

    function testGrantDefaultAdminRole() public {
        cubeContract.DEFAULT_ADMIN_ROLE();

        bool isActive = cubeContract.s_isMintingActive();
        assertEq(isActive, true);

        // call admin function with BOB, who's not admin
        // expect it to fail
        bytes4 selector = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        bytes memory expectedError =
            abi.encodeWithSelector(selector, BOB, cubeContract.DEFAULT_ADMIN_ROLE());
        vm.expectRevert(expectedError);
        vm.prank(BOB);
        cubeContract.setIsMintingActive(false);

        // still active, since the tx failed
        bool isActive2 = cubeContract.s_isMintingActive();
        assertEq(isActive2, true);

        // grant admin role to BOB
        vm.startBroadcast(ownerPubKey);
        cubeContract.grantRole(cubeContract.DEFAULT_ADMIN_ROLE(), BOB);
        vm.stopBroadcast();

        // let BOB turn minting to false
        vm.prank(BOB);
        cubeContract.setIsMintingActive(false);

        // should be false
        bool isActive3 = cubeContract.s_isMintingActive();
        assertEq(isActive3, false);
    }

    function testInitializedNFT() public {
        string memory name = cubeContract.name();
        string memory symbol = cubeContract.symbol();

        assertEq("Layer3 CUBE", name);
        assertEq("CUBE", symbol);
    }

    function testSetTrueMintingToTrueAgain() public {
        vm.prank(ownerPubKey);
        cubeContract.setIsMintingActive(true);
        assertEq(cubeContract.s_isMintingActive(), true);
    }

    function testSetFalseMintingToFalseAgain() public {
        vm.startPrank(ownerPubKey);
        cubeContract.setIsMintingActive(false);
        cubeContract.setIsMintingActive(false);
        vm.stopPrank();
        assertEq(cubeContract.s_isMintingActive(), false);
    }

    modifier SetMintingToFalse() {
        vm.startBroadcast(ownerPubKey);
        cubeContract.setIsMintingActive(false);
        vm.stopBroadcast();
        _;
    }

    function _getCubeMintData() internal view returns (CUBE.CubeData[] memory) {
        CUBE.CubeData memory _data = helper.getCubeData({
            _feeRecipient: ALICE,
            _mintTo: BOB,
            factoryAddress: address(factoryContract),
            tokenAddress: address(erc20Mock),
            tokenId: 0,
            tokenType: ITokenType.TokenType.ERC20,
            rakeBps: 0,
            chainId: 137,
            amount: 100
        });
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        cubeData[0] = _data;

        return cubeData;
    }

    struct Message {
        bytes data;
        uint256 nonce;
    }

    function _getCustomSignedCubeMintData(
        address token,
        uint256 tokenId,
        uint256 amount,
        ITokenType.TokenType tokenType,
        uint256 rakeBps,
        uint256 chainId
    ) internal view returns (CUBE.CubeData[] memory, bytes[] memory) {
        CUBE.CubeData memory _data = helper.getCubeData({
            _feeRecipient: ALICE,
            _mintTo: BOB,
            factoryAddress: address(factoryContract),
            tokenAddress: token,
            tokenId: tokenId,
            tokenType: tokenType,
            rakeBps: rakeBps,
            amount: amount,
            chainId: chainId
        });

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        return (cubeData, signatures);
    }

    function _getSignedCubeMintData()
        internal
        view
        returns (CUBE.CubeData[] memory, bytes[] memory)
    {
        CUBE.CubeData memory _data = helper.getCubeData({
            _feeRecipient: ALICE,
            _mintTo: BOB,
            factoryAddress: address(factoryContract),
            tokenAddress: address(erc20Mock),
            tokenId: 0,
            tokenType: ITokenType.TokenType.ERC20,
            rakeBps: 0,
            chainId: 137,
            amount: 100
        });

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        return (cubeData, signatures);
    }

    function testReferralPayouts() public {
        CUBE.CubeData memory _data = helper.getCubeData({
            _feeRecipient: ALICE,
            _mintTo: BOB,
            factoryAddress: address(factoryContract),
            tokenAddress: address(erc20Mock),
            tokenId: 0,
            amount: 100,
            tokenType: ITokenType.TokenType.ERC20,
            rakeBps: 0,
            chainId: 137
        });
        vm.expectRevert(CUBE.CUBE__ExceedsContractBalance.selector);

        helper.processPayouts(_data);
    }

    function testEmptyWithdrawal() public {
        uint256 preBalanceCube = address(cubeContract).balance;
        uint256 preBalance = ownerPubKey.balance;
        vm.prank(ownerPubKey);
        cubeContract.withdraw();
        uint256 postBal = ownerPubKey.balance;
        assertEq(postBal, preBalance - preBalanceCube);
    }

    function testNonAdminWithdrawal() public {
        bytes4 selector = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));
        bytes memory expectedError =
            abi.encodeWithSelector(selector, BOB, cubeContract.DEFAULT_ADMIN_ROLE());
        vm.expectRevert(expectedError);
        vm.prank(BOB);
        cubeContract.withdraw();
    }

    function testEmptyTokenURI() public {
        // get tokenURI for some random non-existing token
        string memory uri = cubeContract.tokenURI(15);
        assertEq(uri, "");
    }

    function testReInitializeContract() public {
        // contract has already been initialized and we expect test to fail
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        cubeContract.initialize("Test", "TEST", "Test", "2", ALICE);
    }

    function testMintWithLowFee() public {
        (CUBE.CubeData[] memory _data, bytes[] memory _sigs) = _getSignedCubeMintData();
        vm.expectRevert(CUBE.CUBE__FeeNotEnough.selector);
        cubeContract.mintCubes{value: 0.0001 ether}(_data, _sigs);
    }

    function testCubeVersion() public {
        string memory v = cubeContract.cubeVersion();
        assertEq(v, "2");
    }

    function testMintWithNoFee() public {
        (CUBE.CubeData[] memory _data, bytes[] memory _sigs) = _getSignedCubeMintData();
        vm.expectRevert(CUBE.CUBE__FeeNotEnough.selector);
        cubeContract.mintCubes(_data, _sigs);
    }
}
