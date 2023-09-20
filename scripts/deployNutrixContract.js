const hre = require("hardhat");
const { ethers } = hre;

async function deploy() {
  const patientNft = await ethers.deployContract("NutrixMedSec", []);
  console.log("Deployed at:");
  console.log(await patientNft.getAddress());
}

deploy().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
