import { chain } from "./deployAndTest/config";

const getExplorerBaseUrl = (): string => {
	return ""
  return chain.blockExplorers.etherscan.url;
};

export const getTxExplorerUrl = (hash: string): string => {
  const baseUrl = getExplorerBaseUrl();
  return `${baseUrl}/tx/${hash}`;
};

export const getTxAddressUrl = (hash: string): string => {
  const baseUrl = getExplorerBaseUrl();
  return `${baseUrl}/address/${hash}`;
};

export const maybeGetEtherscanApiKey = () => {
  switch (chain.id as number) {
    case 1:
    case 5:
      return process.env.ETHERSCAN_API_KEY as string;
    case 137:
      return process.env.POLYGONSCAN_API_KEY as string;
    case 42170:
      return process.env.ARB_NOVA_ETHERSCAN_API_KEY as string;
    default:
      return null;
  }
};
