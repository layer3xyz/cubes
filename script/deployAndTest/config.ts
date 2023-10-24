import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";

export const chain = foundry;

export const privateKey = process.env.PRIVATE_KEY as `0x${string}`;

export const deployerAccount = privateKeyToAccount(privateKey);

export const deployerWallet = createWalletClient({
  account: deployerAccount,
  chain: chain,
  transport: http(),
});
