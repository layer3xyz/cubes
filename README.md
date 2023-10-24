# Layer3 CUBEs

```
   ________  ______  ______
  / ____/ / / / __ )/ ____/
 / /   / / / / __  / __/
/ /___/ /_/ / /_/ / /___
\____/\____/_____/_____/
```

This repository includes the Layer3 CUBE contract.

It is built with Foundry, and aim to use Foundry best practices.

Unlike HardHat, Foundry doesn't need any js scripts. However, since our main consumer is going to be our own TypeScript app, I thought it was appropriate (and convenient) to add a light package.json setup and write some of the scripts in TypeScript.

This repository is very much in progress and the scripts that are here are made in order to make development easier. At some point in the future we're going to optimize the repo more for production use case.


Test with logs

```
forge test -vv
```
