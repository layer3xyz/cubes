import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { goerli } from "viem/chains";

export const chain = goerli;

export const privateKey = process.env.PRIVATE_KEY as `0x${string}`;

export const deployerAccount = privateKeyToAccount(privateKey);

export const deployerWallet = createWalletClient({
  account: deployerAccount,
  chain: chain,
  transport: http(),
});
