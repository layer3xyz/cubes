import { execa } from "execa";
import { goerli, polygon, arbitrum } from "viem/chains";
import { maybeGetEtherscanApiKey } from "./utils";

export const chain = goerli; //arbitrum;
import cubesDeployment from "../out/cubesDeployment.json";

console.log("Verifying contract...");

const go = async () => {
  const etherscanApiKey = process.env.ETHERSCAN_API_KEY

  if (!etherscanApiKey) {
    throw new Error("Missing etherscan api key");
  }

  console.log("stdout: ", [
    "verify-contract",
    "--chain-id",
    chain.id.toString(),
    `--etherscan-api-key`,
    etherscanApiKey,
    cubesDeployment.deployedTo,
  ]);
  const { stdout } = await execa("forge", [
    "verify-contract",
    "--chain-id",
    chain.id.toString(),
    `--etherscan-api-key`,
    etherscanApiKey,
    cubesDeployment.deployedTo,
		"src/CUBE.sol:TestCUBE"
  ]);
  console.log("stdout: ", stdout);

  console.log("Contract deployed and verified!");
};

go();
