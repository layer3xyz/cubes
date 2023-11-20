import { readFile } from "fs/promises";
import {
  createPublicClient,
  getContract,
  http,
  keccak256,
  toBytes,
} from "viem";
import { testCubeABI } from "../../out/wagmiGenerated";
import { generateSignatureForCubeInput } from "../signature";
import { getTxExplorerUrl } from "../utils";
import { chain, deployerWallet } from "./config";

const test = async () => {
  const cubesDeployment = (await readFile(
    "./out/cubesDeployment.json",
    "utf8"
  ).then((f) => JSON.parse(f))) as {
    deployedTo: `0x${string}`;
  };

  console.log("cubesDeployment: ", cubesDeployment);

  const publicClient = createPublicClient({
    chain: chain,
    transport: http(),
  });

  const contract = getContract({
    address: cubesDeployment.deployedTo as `0x${string}`,
    abi: testCubeABI,
    publicClient: deployerWallet,
    walletClient: deployerWallet,
  });

  const questId = 123n;

  const PROD_RELAYER = "0x1796A56B5446A4D7D32914aa645Ba1d3730aE81D";
  const DEV_RELAYER = "0x0FAfE28eCC76de5FB3047a11074Ba1ee79677058";

  await contract.simulate
    .grantRole([keccak256(toBytes("SIGNER_ROLE")), PROD_RELAYER])
    .then(async ({ request }) => {
      const hash = await deployerWallet.writeContract(request);
      await publicClient.waitForTransactionReceipt({ hash });
      console.log("Role granted to prod relayer: ", getTxExplorerUrl(hash));
    });

  await contract.simulate
    .grantRole([keccak256(toBytes("SIGNER_ROLE")), DEV_RELAYER])
    .then(async ({ request }) => {
      const hash = await deployerWallet.writeContract(request);
      await publicClient.waitForTransactionReceipt({ hash });
      console.log("Role granted to dev relayer: ", getTxExplorerUrl(hash));
    });

  await contract.simulate
    .initializeQuest([
      questId,
      [
        {
          communityName: "Test community 3",
        },
        {
          communityName: "Test community 4",
        },
        {
          communityName: "Test community 5",
        },
        {
          communityName: "Test community 6",
        },
      ],
      "This is a quest with no tags and lots of communities",
      1,
      0,
    ])
    .then(async ({ request }) => {
      const hash = await deployerWallet.writeContract(request);
      await publicClient.waitForTransactionReceipt({ hash });
      console.log("Quest initialized: ", getTxExplorerUrl(hash));
    });

  const fee = 777n;

  const userId = 483n;

  const cubeInput = {
    questId,
    userId,
    walletName: "Test Wallet",
    steps: [
      {
        stepTxHash:
          "0x9ea5aafdcdf8195836c63221e390fcd141c77d70152d65e51d99021ad79d5e06",
        stepChainId: 1n,
      },
      {
        stepTxHash:
          "0xd22a82c8ed2fe3c3aeec9b77dc153b32975c2ccd543214d5122e7d90772ccebd",
        stepChainId: 8453n,
      },
    ] as const,
    tokenUri: "",
    timestamp: 123n,
  };

  // Sign the CubeInputData object itself.
  const signature = await generateSignatureForCubeInput(
    deployerWallet,
    cubeInput
  );

  await contract.simulate
    .mintMultipleCubes([[cubeInput], [signature]], {
      value: fee * 1n,
    })
    .then(async ({ request }) => {
      const hash = await deployerWallet.writeContract(request);
      await publicClient.waitForTransactionReceipt({ hash });
      console.log("Quest completed: ", getTxExplorerUrl(hash));
    });
};

test();
