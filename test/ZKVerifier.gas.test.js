// Gas benchmark for Groth16Verifier.verifyProof() using proof artifacts from build/circuits/.

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("Groth16Verifier — on-chain gas benchmark", function () {
    let verifier, proof, pub;

    before(async function () {
        // Load pre-generated proof
        proof = JSON.parse(fs.readFileSync(path.join(__dirname, "../build/circuits/proof.json")));
        pub   = JSON.parse(fs.readFileSync(path.join(__dirname, "../build/circuits/public.json")));

        const Verifier = await ethers.getContractFactory("Groth16Verifier");
        verifier = await Verifier.deploy();
        await verifier.deployed();
    });

    it("measures verifyProof gas (10 calls)", async function () {
        const pA = [proof.pi_a[0], proof.pi_a[1]];
        const pB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
        const pC = [proof.pi_c[0], proof.pi_c[1]];
        const pubSignals = pub;

        // Assert proof is actually valid before measuring gas
        const isValid = await verifier.verifyProof(pA, pB, pC, pubSignals);
        expect(isValid).to.equal(true, "verifyProof returned false — proof/pubSignals mismatch");

        const gasReadings = [];
        for (let i = 0; i < 10; i++) {
            const gas = await verifier.estimateGas.verifyProof(pA, pB, pC, pubSignals);
            gasReadings.push(Number(gas));
        }
        const mean = Math.round(gasReadings.reduce((a, b) => a + b, 0) / gasReadings.length);
        const min  = Math.min(...gasReadings);
        const max  = Math.max(...gasReadings);
        console.log(`\n  Gas estimate per verifyProof call:`);
        gasReadings.forEach((g, i) => console.log(`    Run ${i+1}: ${g.toLocaleString()} gas`));
        console.log(`  Mean: ${mean.toLocaleString()} | Min: ${min.toLocaleString()} | Max: ${max.toLocaleString()}`);
        expect(mean).to.be.lessThan(500000);
    });
});
