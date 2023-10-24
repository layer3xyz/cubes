import { execa } from "execa";
import { writeFile } from "fs/promises";
import { polygon } from "viem/chains";
import { testCubeABI } from "../../out/wagmiGenerated";
import { getTxAddressUrl, maybeGetEtherscanApiKey } from "../utils";
import { chain, privateKey } from "./config";
import { deployerAccount } from "./config";


console.log("Deploying contract...");

const etherscanApiKey = maybeGetEtherscanApiKey();
const shouldVerify = !!etherscanApiKey;

if (!shouldVerify) {
  console.log("Skipping verification...");
}

console.log("account address: ", deployerAccount.address);

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
