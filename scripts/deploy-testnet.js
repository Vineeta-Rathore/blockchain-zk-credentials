'use strict';

/*
 * Deploy Groth16Verifier, ZKVerifier, and DIDRegistry to Ethereum Sepolia.
 * Groth16Verifier is deployed first; its address is passed to ZKVerifier.
 *
 * Usage:
 *   npx hardhat run scripts/deploy-testnet.js --network sepolia
 *
 * Prerequisites:
 *   SEPOLIA_RPC_URL and PRIVATE_KEY must be set in .env (see README.md)
 */

const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
    const [deployer] = await ethers.getSigners();
    const network = await ethers.provider.getNetwork();

    console.log("Network:", network.name, "(chain", network.chainId + ")");
    console.log("Deployer:", deployer.address);

    const balance = await deployer.getBalance();
    console.log("Balance:", ethers.utils.formatEther(balance), "ETH");

    if (balance.eq(0)) {
        console.error("Deployer has no balance. Get Sepolia ETH from https://sepoliafaucet.com/");
        process.exit(1);
    }

    // Deploy Groth16Verifier first (no constructor args)
    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const groth16 = await Groth16Verifier.deploy();
    await groth16.deployed();
    console.log("Groth16Verifier:", groth16.address);

    // Deploy ZKVerifier with Groth16Verifier address
    const ZKVerifier = await ethers.getContractFactory("ZKVerifier");
    const zkVerifier = await ZKVerifier.deploy(groth16.address);
    await zkVerifier.deployed();
    console.log("ZKVerifier:      ", zkVerifier.address);

    // Deploy DIDRegistry (companion system foundation layer)
    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    const didRegistry = await DIDRegistry.deploy();
    await didRegistry.deployed();
    console.log("DIDRegistry:     ", didRegistry.address);

    const deploymentInfo = {
        network: network.name,
        chainId: network.chainId,
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {
            Groth16Verifier: groth16.address,
            ZKVerifier: zkVerifier.address,
            DIDRegistry: didRegistry.address,
        },
        blockExplorer: "https://sepolia.etherscan.io",
    };

    const deploymentDir = path.join(__dirname, "..", "deployments");
    if (!fs.existsSync(deploymentDir)) fs.mkdirSync(deploymentDir, { recursive: true });

    const filename = `deployment-${network.name}-${Date.now()}.json`;
    fs.writeFileSync(path.join(deploymentDir, filename), JSON.stringify(deploymentInfo, null, 2));
    console.log("Saved:", path.join("deployments", filename));

    console.log("\nVerify on Etherscan:");
    console.log(`  npx hardhat verify --network sepolia ${groth16.address}`);
    console.log(`  npx hardhat verify --network sepolia ${zkVerifier.address} "${groth16.address}"`);
    console.log(`  npx hardhat verify --network sepolia ${didRegistry.address}`);
}

main()
    .then(() => process.exit(0))
    .catch(err => { console.error(err); process.exit(1); });
