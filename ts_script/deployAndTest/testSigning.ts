import { readFile } from "fs/promises";
import { getContract } from "viem";
import { testCubeABI } from "../../out/wagmiGenerated";
import { generateSignatureForCubeInput } from "../signature";
import { deployerWallet } from "./config";

const cubesDeployment = (await readFile(
  "./out/cubesDeployment.json",
  "utf8"
).then((f) => JSON.parse(f))) as {
  deployedTo: `0x${string}`;
};

const contract = getContract({
  address: cubesDeployment.deployedTo as `0x${string}`,
  abi: testCubeABI,
  publicClient: deployerWallet,
  walletClient: deployerWallet,
});

const questId = 123n;

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
};

const test = async () => {
  const signedMessage = await generateSignatureForCubeInput(
    deployerWallet,
    cubeInput
  );

  const recoveredSignerFromChain = await contract.read._recover([
    cubeInput,
    signedMessage,
  ]);

  if (recoveredSignerFromChain !== deployerWallet.account.address) {
    throw new Error("Recovered signer does not match actual signer");
  }

  console.log("✅ Signing test passed!");
};

test();
