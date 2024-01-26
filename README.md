```
   ________  ______  ______
  / ____/ / / / __ )/ ____/
 / /   / / / / __  / __/
/ /___/ /_/ / /_/ / /___
\____/\____/_____/_____/
```

## Install

```bash
make install
make build
```

### Deployment

```bash
make deploy_proxy ARGS="--network base_sepolia"
```

### Test

```bash
make test
```

## Description

At Layer3, users can complete different quests (different questions about the web3 landscape, or actions to be made on different chains). When completing a quest, some of them allows users to mint a CUBE. A CUBE is an NFT containing all sorts of data related to the completed quest. An example of a quest can be seen [here on Opensea](https://opensea.io/assets/base/0x1195cf65f83b3a5768f3c496d3a05ad6412c64b7/95).

When minting a CUBE, an EIP712 message is signed in the Layer3 app, containing all CUBE data related to the quest that is needed to perform the minting (the function `mintCubes`). The user then sends the transaction with this signature and data. Currently, there's no immediate utility behind a CUBE, but this might change in the future.

Other than having a cool NFT as a proof that you completed a quest, the minting transaction emit events in the smart contract which are caught by Dune Analytics. Displaying this data is important and a big part of the CUBE smart contract, since it adds concrete numbers on user base, engagement and more importantly it gives users provenance on chain.

When a quest is created in our backend, the function `initializeQuest` is called. The only purpose of this function is to emit event data about the quest, such as what communities are involved (e.g. Layer3, Uniswap, 1Inch), together with showing the difficulty of the quest (beginner, intermediate, advanced), title etc.

## Smart Contract Overview

### Key Features

- Quest Completion and CUBE Minting: Users complete quests and mint CUBEs as a proof of their achievements.
- EIP712 Signatures: Utilizes EIP712 to sign data.
- Dune Analytics Integration: Events emitted by the contract are captured for analytics, providing insights into user engagement and activity.
- Referral System: Incorporates a referral mechanism in the minting process.

### Contract Specification

- Contract Name: CUBE
- Version: 0.8.20 (Paris)
- Optimizations: Yes, 10,000 runs.
- License: MIT
- Upgradeable: Yes, using OpenZeppelin's UUPSUpgradeable pattern.

### Roles and Permissions

- Default Admin: Full control over the contract, including upgrading and setting token URIs.
- Signer: Authorized to initialize quests and sign cube data for minting.
- Upgrader: Can upgrade the contract
