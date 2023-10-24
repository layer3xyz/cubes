import { execa } from "execa";
import { writeFile } from "fs/promises";
import {
  SignableMessage,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  getContract,
  http,
} from "viem";
import { privateKeyToAccount, signMessage } from "viem/accounts";
import { goerli, polygon, arbitrum, base } from "viem/chains";
import { testCubeABI } from "../out/wagmiGenerated";
import {
  getTxAddressUrl,
  getTxExplorerUrl,
  maybeGetEtherscanApiKey,
} from "./utils";

export const chain = polygon; //arbitrum;

const privateKey = process.env.PRIVATE_KEY as `0x${string}`;

console.log("Deploying contract...");

const etherscanApiKey = maybeGetEtherscanApiKey();
const shouldVerify = !!etherscanApiKey;

if (!shouldVerify) {
  console.log("Skipping verification...");
}

const account = privateKeyToAccount(privateKey);
console.log("account address: ", account.address);

const { stdout } = await execa("forge", [
  "create",
  "--rpc-url",
  chain.rpcUrls.default.http[0],
  "--private-key",
  privateKey,
  ...(shouldVerify ? ["--verify", `--etherscan-api-key`, etherscanApiKey] : []),
  "--json",
  "src/CUBE.sol:TestCUBE",
]);

console.log("Contract deployed and verified!");

const firstLine = stdout.split("\n")[0];
const deploymentInfo = JSON.parse(firstLine) as { deployedTo: string };
// const deploymentInfo = {
//   deployer: "0x336594F599CcD76F88344F9A767CEd2463389233",
//   deployedTo: "0xF6733DB2651A247998644290b516DfC01fd9f6c1",
//   transactionHash:
//     "0x4134701a7511364f09f37fd2fbd33a2d547be88a871b1e21321e92b8efa71caf",
// };
//

console.log(
  "Using contract: ",
  `${deploymentInfo.deployedTo} ${getTxAddressUrl(deploymentInfo.deployedTo)}`
);

await writeFile("./out/cubesDeployment.json", JSON.stringify(deploymentInfo));
await writeFile("./out/cubes.abi.json", JSON.stringify(testCubeABI));

const walletClient = createWalletClient({
  account,
  chain: chain,
  transport: http(),
});

const publicClient = createPublicClient({
  chain: chain,
  transport: http(),
});

const contract = getContract({
  address: deploymentInfo.deployedTo as `0x${string}`,
  abi: testCubeABI,
  publicClient: walletClient,
  walletClient: walletClient,
});

const questId = 123n;

await contract.simulate
  .initializeQuest([
    questId,
    [
      {
        communityId: 33,
        communityName: "Test community 3",
      },
      {
        communityId: 34,
        communityName: "Test community 4",
      },
      {
        communityId: 35,
        communityName: "Test community 5",
      },
      {
        communityId: 36,
        communityName: "Test community 6",
      },
    ],
    "This is a quest with no tags and lots of communities",
    1,
    0,
  ])
  .then(async ({ request }) => {
    const hash = await walletClient.writeContract(request);
    await publicClient.waitForTransactionReceipt({ hash });
    console.log("Quest initialized: ", getTxExplorerUrl(hash));
  });

const fee = 777n;

const userId = 483n;

// walletClient.sign

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
};

// // Sign the CubeInputData object itself.
const signature = `0x1234`;

await contract.simulate
  .mintMultipleCubes(
    [
      [cubeInput],
      [signature],
    ],
    {
      value: fee * 1n,
    }
  )
  .then(async ({ request }) => {
    const hash = await walletClient.writeContract(request);
    await publicClient.waitForTransactionReceipt({ hash });
    console.log("Quest completed: ", getTxExplorerUrl(hash));
  });
