import { execa } from "execa";
import { goerli } from "viem/chains";
import cubesDeployment from "../out/cubesDeployment.json";

export const chain = goerli; //arbitrum;

console.log("Verifying contract...");

const go = async () => {
  const etherscanApiKey = process.env.ETHERSCAN_API_KEY;

  if (!etherscanApiKey) {
    throw new Error("Missing etherscan api key");
  }

  const { stdout } = await execa("forge", [
    "verify-contract",
    "--chain-id",
    chain.id.toString(),
    `--etherscan-api-key`,
    etherscanApiKey,
    cubesDeployment.deployedTo,
    "src/CUBE.sol:TestCUBE",
  ]);
  console.log("stdout: ", stdout);

  console.log("Contract verified!");
};

go();
