// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {Test, console, Vm} from "forge-std/Test.sol";
import {CUBE} from "../../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Helper} from "../utils/Helper.t.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
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
        CUBE.TokenType tokenType
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

    // Test Users
    address public adminAddress;
    address public constant ADMIN = address(1);
    uint256 internal adminPrivateKey;
    address public constant ALICE = address(2);
    address public constant BOB = address(3);

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

        helper = new Helper();
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

    function testMintCubes() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        bool isSigner = cubeContract.hasRole(keccak256("SIGNER"), adminAddress);
        assertEq(isSigner, true);

        hoax(adminAddress, 10 ether);

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        assertEq(cubeContract.tokenURI(0), "ipfs://abc");
        assertEq(cubeContract.ownerOf(0), BOB);
    }

    function testMintCubesRewardEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting TokenReward event to be emitted
        vm.expectEmit(true, true, true, true);
        emit TokenReward(0, address(0), 137, 5, 0, CUBE.TokenType.NATIVE);

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMintCubesTxEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting CubeTransaction event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CubeTransaction(
            0, "0xe265a54b4f6470f7f52bb1e4b19489b13d4a6d0c87e6e39c5d05c6639ec98002", "evm:137"
        );

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMintCubesClaimEvent() public {
        (CUBE.CubeData[] memory cubeData, bytes[] memory signatures) = _getSignedCubeMintData();

        hoax(adminAddress, 10 ether);

        // Expecting TokenReward events to be emitted
        vm.expectEmit(true, true, true, true);
        emit CubeClaim(1, 0, BOB, 1, "MetaMask", "test.com");

        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testNonceReuse() public {
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = helper.getTestCubeData(BOB, ALICE);

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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = helper.getTestCubeData(BOB, ALICE);
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
        assertEq(cubeContract.ownerOf(1), ALICE);
    }

    function testMismatchCubeDataAndSignatureArray() public {
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = helper.getTestCubeData(BOB, ALICE);

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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = helper.getTestCubeData(BOB, ALICE);

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
        CUBE.CubeData memory _data = helper.getTestCubeData(ALICE, BOB);

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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        assertEq(ALICE.balance, 10 ether * 0.05); // 5%
        assertEq(BOB.balance, 10 ether * 0.4); // 40%
        assertEq(adminAddress.balance, 10 ether * 0.4); // 40%
    }

    function testExceedContractBalance() public {
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);
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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);

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
        CUBE.CubeData memory data = helper.getTestCubeData(ALICE, BOB);

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
        CUBE.CubeData memory _data = helper.getTestCubeData(ALICE, BOB);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);

        _data.recipients = new CUBE.FeeRecipient[](3);
        _data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        _data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 800});
        _data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 1000});

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        cubeData[0] = _data;
        signatures[0] = signature;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        uint256 expectedBalAlice = 10 ether * 0.05;
        assertEq(ALICE.balance, expectedBalAlice);
        uint256 expectedBalBob = 10 ether * 0.08;
        assertEq(BOB.balance, expectedBalBob);
        uint256 expectedBalAdmin = 10 ether * 0.1;
        assertEq(adminAddress.balance, expectedBalAdmin);
        // 23% taken by referrers, so 77% should be left
        uint256 expectedMintProfit = 10 ether * 0.77;
        assertEq(proxyAddress.balance, expectedMintProfit);

        vm.prank(ownerPubKey);
        cubeContract.withdraw();

        assertEq(ownerPubKey.balance, expectedMintProfit);
        assertEq(proxyAddress.balance, 0);
    }

    function testReferralFees() public {
        CUBE.CubeData memory _data = helper.getTestCubeData({_feeRecipient: ALICE, _mintTo: BOB});

        bytes32 structHash = helper.getStructHash(_data);
        bytes32 digest = helper.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        // send from admin
        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        uint256 balanceAlice = ALICE.balance;
        uint256 balanceContract = proxyAddress.balance;

        // 33% of 10 ether
        uint256 expectedBal = 10 ether * 0.33;

        assertEq(balanceAlice, expectedBal);
        assertEq(balanceContract, 10 ether - expectedBal);
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
        vm.startBroadcast(ownerPubKey);
        cubeContract.setIsMintingActive(true);
        vm.stopBroadcast();
        assertEq(cubeContract.s_isMintingActive(), true);
    }

    function testSetFalseMintingToFalseAgain() public {
        vm.startBroadcast(ownerPubKey);
        cubeContract.setIsMintingActive(false);
        cubeContract.setIsMintingActive(false);
        vm.stopBroadcast();
        assertEq(cubeContract.s_isMintingActive(), false);
    }

    modifier SetMintingToFalse() {
        vm.startBroadcast(ownerPubKey);
        cubeContract.setIsMintingActive(false);
        vm.stopBroadcast();
        _;
    }

    function _getCubeMintData() internal view returns (CUBE.CubeData[] memory) {
        CUBE.CubeData memory _data = helper.getTestCubeData({_feeRecipient: ALICE, _mintTo: BOB});
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        cubeData[0] = _data;

        return cubeData;
    }

    function _getSignedCubeMintData()
        internal
        view
        returns (CUBE.CubeData[] memory, bytes[] memory)
    {
        CUBE.CubeData memory _data = helper.getTestCubeData({_feeRecipient: ALICE, _mintTo: BOB});

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
        CUBE.CubeData memory _data = helper.getTestCubeData({_feeRecipient: ALICE, _mintTo: BOB});
        vm.expectRevert(CUBE.CUBE__ExceedsContractBalance.selector);

        helper.processPayouts(_data);
    }

    function testEmptyWithdrawal() public {
        uint256 preBal = ownerPubKey.balance;
        console.log(preBal);
        vm.prank(ownerPubKey);
        cubeContract.withdraw();
        uint256 postBal = ownerPubKey.balance;
        console.log(postBal);
        assertEq(preBal, postBal);
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
        cubeContract.mintCubes{value: 8 ether}(_data, _sigs);
    }

    function testMintWithNoFee() public {
        (CUBE.CubeData[] memory _data, bytes[] memory _sigs) = _getSignedCubeMintData();
        vm.expectRevert(CUBE.CUBE__FeeNotEnough.selector);
        cubeContract.mintCubes(_data, _sigs);
    }
}
