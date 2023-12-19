```
   ________  ______  ______
  / ____/ / / / __ )/ ____/
 / /   / / / / __  / __/
/ /___/ /_/ / /_/ / /___
\____/\____/_____/_____/
```

# CUBE Project Description

At Layer3, users can complete different quests (different questions about the web3 landscape, or actions to be made on different chains). When completing a quest, some of them allows users to mint a CUBE. A CUBE is an NFT containing all sorts of data related to the completed quest. An example of a quest can be seen here on Opensea (goerli testnet): [https://testnets.opensea.io/assets/goerli/0x97024f5be3f5406a36515254910b9655c69f16ce/55](https://testnets.opensea.io/assets/goerli/0x97024f5be3f5406a36515254910b9655c69f16ce/55)

When minting a cube, we have an admin wallet in our backend that signs an EIP712 message with the cube data that is needed to mint a cube (the function `mintCubes`). The user is then the one sending the transaction, pays for gas and also a minting fee which is set in our backend. Once they have sent the transaction, they wait for the transaction to be mined and then they see the UI updating with their freshly minted CUBE. Currently, there's no immediate utility behind a CUBE, but this might change in the future.

Other than having a cool NFT as a proof that you completed a quest, the minting transaction emit events in the smart contract and we catch these in Dune Analytics. Displaying this data is important and a big part of the CUBE smart contract, since it adds concrete numbers on user base, engagement and more importantly it gives users provenance on chain.

When a quest is created in our backend (currently only supported by Layer3 admins), the function `initializeQuest` is called. The only purpose of this function is to emit event data about the quest, such as what communities are involved (Layer3, Uniswap, 1Inch etc.), together with showing the difficulty of the quest (beginner, intermediate, advanced), title and so on.

## Smart Contract Overview

### Key Features

- Quest Completion and CUBE Minting: Users complete quests and mint CUBEs as proof of their achievements.
- EIP712 Signatures: Utilizes EIP712 for secure signing of transactions.
- Dune Analytics Integration: Events emitted by the contract are captured for analytics, providing insights into user engagement and activity.
- Referral System: Incorporates a referral mechanism in the minting process.

### Contract Specification

- Deploying Network: OP Mainnet, Base or Polygon
- Contract Name: CUBE
- Version: 0.8.20 (paris)
- Optimizations: Yes, 10,000 runs.
- License: MIT
- Upgradeable: Yes, using OpenZeppelin's UUPSUpgradeable pattern.

### Roles and Permissions

- Admin: Full control over the contract, including upgrading and setting token URIs.
- Signer: Authorized to initialize quests and sign cube data for minting.

## Diagrams

![Solidity Visual Developer, CSV from draw.io](/draw_io.png)
![Solidity Visual Developer, UML](/uml.png)
