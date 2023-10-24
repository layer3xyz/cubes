import { defineConfig } from "@wagmi/cli";
import { foundry } from "@wagmi/cli/plugins";

export default defineConfig({
  out: "out/wagmiGenerated.ts",
  contracts: [],
  plugins: [
    foundry({
      include: ["TestCUBE.json"],
    }),
  ],
});
