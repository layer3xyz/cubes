// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {DeployProxy} from "../../script/DeployProxy.s.sol";
import {Test, console, Vm} from "forge-std/Test.sol";
import {CUBE} from "../../src/CUBE.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessagehashUtils.sol";
import {SigUtils} from "../utils/Signature.t.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract CubeTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /* EVENTS */
    event QuestMetadata(
        uint256 indexed questId,
        CUBE.QuestType questType,
        CUBE.Difficulty difficulty,
        string title,
        string[] tags
    );
    event QuestCommunity(uint256 indexed questId, string communityName);
    event CubeClaim(
        uint256 indexed questId,
        uint256 indexed tokenId,
        uint256 issueNumber,
        uint256 userId,
        uint256 completedAt,
        string walletName,
        string embedOrigin
    );
    event CubeTransaction(uint256 indexed tokenId, bytes32 indexed txHash, uint256 indexed chainId);

    DeployProxy public deployer;
    CUBE public cubeContract;

    string constant SIGNATURE_DOMAIN = "LAYER3";
    string constant SIGNING_VERSION = "1";

    SigUtils internal sigUtils;

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

        deployer = new DeployProxy();
        proxyAddress = deployer.deployProxy(ownerPubKey);
        cubeContract = CUBE(payable(proxyAddress));

        sigUtils = new SigUtils();
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

        // Expecting QuestCommunity and QuestMetadata events to be emitted
        vm.expectEmit(true, true, false, true);
        emit QuestCommunity(questId, communities[0]);
        emit QuestCommunity(questId, communities[1]);
        vm.expectEmit(true, true, false, true);
        emit QuestMetadata(questId, questType, difficulty, title, tags);

        vm.prank(ownerPubKey);
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
        CUBE.CubeData memory _data = sigUtils.getTestCubeData(ALICE, BOB);

        bytes32 structHash = sigUtils.getStructHash(_data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);
        cubeData[0] = _data;
        signatures[0] = signature;

        bool isSigner = cubeContract.hasRole(keccak256("SIGNER"), ownerPubKey);
        assertEq(isSigner, true);

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);

        assertEq(cubeContract.tokenURI(0), "ipfs://abc");
        assertEq(cubeContract.ownerOf(0), BOB);
    }

    function testNonceReuse() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(ALICE, BOB);
        data.nonce = 1;
        data2.nonce = 1;

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = sigUtils.getStructHash(data2);
        bytes32 digest2 = sigUtils.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPrivateKey, digest2);
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

    function testNonceReuseDifferentSigners() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(BOB, ALICE);

        data.nonce = 1;
        data2.nonce = 1;

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = sigUtils.getStructHash(data2);
        bytes32 digest2 = sigUtils.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPrivateKey, digest2);
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

    function testMultipleCubeDataMint() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(BOB, ALICE);
        data2.nonce = 32142;

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = sigUtils.getStructHash(data2);
        bytes32 digest2 = sigUtils.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPrivateKey, digest2);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(BOB, ALICE);

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(BOB, ALICE);

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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

    function testEmptyCubeDataTxs() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.transactions = new CUBE.TransactionData[](1);

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testEmptyReferrals() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.recipients = new CUBE.FeeRecipient[](1);

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);

        signatures[0] = signature;
        cubeData[0] = data;

        hoax(adminAddress, 10 ether);
        cubeContract.mintCubes{value: 10 ether}(cubeData, signatures);
    }

    function testMultipleRefPayouts() public {
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 4000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 8000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 8000});

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({
            recipient: BOB,
            BPS: 10_001 // max is 10k
        });
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        data.recipients = new CUBE.FeeRecipient[](3);
        data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 9000});
        data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 4000});

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory data = sigUtils.getTestCubeData(ALICE, BOB);
        CUBE.CubeData memory data2 = sigUtils.getTestCubeData(BOB, ALICE);
        data2.nonce = 3;

        bytes32 structHash = sigUtils.getStructHash(data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 structHash2 = sigUtils.getStructHash(data2);
        bytes32 digest2 = sigUtils.getDigest(getDomainSeparator(), structHash2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPrivateKey, digest2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        bytes[] memory signatures = new bytes[](2);
        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](2);

        signatures[0] = signature;
        signatures[1] = signature2;
        cubeData[0] = data;
        cubeData[1] = data2;

        hoax(adminAddress, 20 ether);
        //vm.expectRevert(CUBE.CUBE__NonceAlreadyUsed.selector);
        cubeContract.mintCubes{value: 20 ether}(cubeData, signatures);
    }

    function testMultipleReferrers() public {
        CUBE.CubeData memory _data = sigUtils.getTestCubeData(ALICE, BOB);

        CUBE.CubeData[] memory cubeData = new CUBE.CubeData[](1);
        bytes[] memory signatures = new bytes[](1);

        _data.recipients = new CUBE.FeeRecipient[](3);
        _data.recipients[0] = CUBE.FeeRecipient({recipient: ALICE, BPS: 500});
        _data.recipients[1] = CUBE.FeeRecipient({recipient: BOB, BPS: 800});
        _data.recipients[2] = CUBE.FeeRecipient({recipient: adminAddress, BPS: 1000});

        bytes32 structHash = sigUtils.getStructHash(_data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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
        CUBE.CubeData memory _data = sigUtils.getTestCubeData({_feeRecipient: ALICE, _mintTo: BOB});

        bytes32 structHash = sigUtils.getStructHash(_data);
        bytes32 digest = sigUtils.getDigest(getDomainSeparator(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
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

    function testInitalizeQuestLogs() public {
        uint256 questId = 777;
        string[] memory communities = new string[](1);
        communities[0] = "Community1";
        string memory title = "Quest Title";
        string[] memory tags = new string[](1);
        tags[0] = "NFTs";
        CUBE.Difficulty difficulty = CUBE.Difficulty.BEGINNER;
        CUBE.QuestType questType = CUBE.QuestType.QUEST;
        vm.recordLogs();
        vm.prank(ownerPubKey);
        cubeContract.initializeQuest(questId, communities, title, difficulty, questType, tags);

        Vm.Log[] memory entries = vm.getRecordedLogs();

        // the emitted questId value
        assert(uint256(entries[1].topics[1]) == questId);
    }

    function testTurnOffMinting() public {
        bool isActive = cubeContract.s_isMintingActive();

        console.logBool(isActive);
        vm.prank(ownerPubKey);
        cubeContract.setIsMintingActive(false);

        bool isActiveUpdated = cubeContract.s_isMintingActive();
        console.logBool(isActiveUpdated);

        assert(isActiveUpdated != isActive);
    }

    function test721Interface() public view {
        bool supportsInterface = cubeContract.supportsInterface(type(IERC721).interfaceId);
        assert(supportsInterface == true);
    }

    function testRevokeAdminRole() public {
        bytes32 signerRole = keccak256("SIGNER");
        bool isSigner = cubeContract.hasRole(signerRole, ownerPubKey);
        assertEq(isSigner, true);

        vm.prank(ownerPubKey);
        cubeContract.renounceRole(signerRole, ownerPubKey);
    }
}
