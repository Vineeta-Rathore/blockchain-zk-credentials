'use strict';

/*
 * Deploy Groth16Verifier, ZKVerifier, and DIDRegistry to a local Hardhat node.
 * Groth16Verifier must be deployed first; its address is passed to ZKVerifier.
 *
 * Usage:
 *   npx hardhat node
 *   npx hardhat run scripts/deploy.js --network localhost
 */

const { ethers } = require("hardhat");

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deployer:", deployer.address);

    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const groth16 = await Groth16Verifier.deploy();
    await groth16.deployed();
    console.log("Groth16Verifier:", groth16.address);

    const ZKVerifier = await ethers.getContractFactory("ZKVerifier");
    const zkVerifier = await ZKVerifier.deploy(groth16.address);
    await zkVerifier.deployed();
    console.log("ZKVerifier:      ", zkVerifier.address);

    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    const didRegistry = await DIDRegistry.deploy();
    await didRegistry.deployed();
    console.log("DIDRegistry:     ", didRegistry.address);
}

main()
    .then(() => process.exit(0))
    .catch(err => { console.error(err); process.exit(1); });
