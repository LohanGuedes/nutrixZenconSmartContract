# NutrixZen

This repo holes the technology that will change the lives of nutrix patients, as well as intructions on how to deploy it to zeniq smartchain

## Install Dependencies:

```shell
npm install
```

These are the dependencies that will be installed by default

```shell
  "devDependencies": {
    "@nomiclabs/hardhat-ethers": "^2.2.3",
    "@truffle/dashboard-hardhat-plugin": "^0.2.15",
    "dotenv": "^16.3.1",
    "ethers": "^5.7.2",
    "hardhat": "^2.17.3",
    "truffle": "^5.11.5"
  },
  "dependencies": {
    "@openzeppelin/contracts": "^4.9.3",
    "nft.storage": "^7.1.1"
  }
```

## Compile the project

```shell
npx hardhat compile
```

## Deploy using Truffle Dashboard

Open the terminal and run:

```shell
truffle dashboard
```

This command will open the Dashboard in your browser, connect your metamask to the desired network
and click "Click to connect" to link your metamask to the Dashboard

Be sure to have zeniq smartchain in your metamask account.

Open a new terminal and run:

```shell
npx hardhat run scripts/deployNutrixContract.js --network truffleDashboard
```

Go back to the localhost:[PORT] in which truffleDashboard is running and either confirm the transaction in order to deploy your contract.
