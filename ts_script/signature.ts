import { encodePacked, keccak256 } from "viem";
import { deployerWallet } from "./deployAndTest/config";

// todo: infer this from somewhere
type CubeInput = {
  questId: bigint;
  userId: bigint;
  walletName: string;
  steps: readonly {
    stepTxHash: string;
    stepChainId: bigint;
  }[];
};

const encodeCubeInput = (cubeInput: CubeInput) => {
  return encodePacked(
    ["uint256", "uint256", "string"],
    [cubeInput.questId, cubeInput.userId, cubeInput.walletName]
  );
};

export const generateSignatureForCubeInput = async (
  wallet: typeof deployerWallet,
  cubeInput: CubeInput
) => {
  const encodedData = encodeCubeInput(cubeInput);
  const signedMessage = await wallet.signMessage({
    message: {
      raw: keccak256(encodedData),
    },
  });

  return signedMessage;
};
