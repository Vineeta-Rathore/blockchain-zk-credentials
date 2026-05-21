/**
 * @journal JOURNAL 3 — Privacy-Preserving ZK Credential Verification
 *
 * Role: Full end-to-end gas benchmark for ZKVerifier.verifyCredentialProof().
 *   Measures TOTAL on-chain cost including:
 *     - Trusted issuer SLOAD check
 *     - Credential registry SLOAD check
 *     - Scope nullifier (ban) SLOAD check
 *     - Session nullifier SLOAD check
 *     - Groth16Verifier.verifyProof() (EIP-197 pairing — 396,197 gas)
 *     - Session nullifier SSTORE (mark used)
 *     - VerificationResult SSTORE (audit history)
 *     - ProofVerified + NullifierUsed LOG4/LOG3 events
 *
 *   Also measures:
 *     - addTrustedIssuer() gas
 *     - registerCredential() gas  (new after Option A fix)
 *     - banUser() gas
 *
 * STATUS: VALID — uses real proof artifacts from build/circuits/
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("ZKVerifier — full end-to-end gas benchmark", function () {
    let zkVerifier, groth16Verifier;
    let proof, pub;
    let admin, user;

    // Loaded from benchmark output
    let issuerPublicKey, credentialCommitment, scopeNullifier, platformId;
    let pA, pB, pC, inputs;

    before(async function () {
        [admin, user] = await ethers.getSigners();

        // Load real proof artifacts
        proof = JSON.parse(fs.readFileSync(
            path.join(__dirname, "../build/circuits/proof.json")));
        pub = JSON.parse(fs.readFileSync(
            path.join(__dirname, "../build/circuits/public.json")));

        // pubSignals layout (nPublic=27):
        // [0] credentialValid, [1] nullifier, [2-9] attrCommitments,
        // [10-17] revealedValues, [18] predicateSatisfied, [19] scopeNullifier,
        // [20] issuerPublicKey, [21] schemaHash, [22] challenge,
        // [23] predicateThreshold, [24] predicateAttributeIndex,
        // [25] credentialCommitment, [26] platformId
        issuerPublicKey      = pub[20];
        credentialCommitment = pub[25];
        scopeNullifier       = pub[19];
        platformId           = pub[26];

        pA = [proof.pi_a[0], proof.pi_a[1]];
        pB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
        pC = [proof.pi_c[0], proof.pi_c[1]];

        // Deploy Groth16Verifier
        const Groth16 = await ethers.getContractFactory("Groth16Verifier");
        groth16Verifier = await Groth16.deploy();
        await groth16Verifier.deployed();

        // Deploy ZKVerifier
        const ZKV = await ethers.getContractFactory("ZKVerifier");
        zkVerifier = await ZKV.deploy(groth16Verifier.address);
        await zkVerifier.deployed();

        // Build PublicInputs struct matching ZKVerifier.sol layout
        inputs = {
            issuerPublicKey:        issuerPublicKey,
            schemaHash:             pub[21],
            challenge:              pub[22],
            predicateThreshold:     pub[23],
            predicateAttributeIndex: pub[24],
            credentialCommitment:   credentialCommitment,
            platformId:             platformId,
            credentialValid:        pub[0],
            nullifier:              pub[1],
            predicateSatisfied:     pub[18],
            scopeNullifier:         scopeNullifier,
            attributeCommitments:   pub.slice(2, 10),
            revealedValues:         pub.slice(10, 18),
        };
    });

    it("addTrustedIssuer() gas", async function () {
        const gas = await zkVerifier.estimateGas.addTrustedIssuer(issuerPublicKey);
        console.log(`\n  addTrustedIssuer():      ${Number(gas).toLocaleString()} gas`);
        await zkVerifier.addTrustedIssuer(issuerPublicKey);
    });

    it("registerCredential() gas", async function () {
        const gas = await zkVerifier.estimateGas.registerCredential(
            issuerPublicKey, credentialCommitment);
        console.log(`  registerCredential():    ${Number(gas).toLocaleString()} gas`);
        await zkVerifier.registerCredential(issuerPublicKey, credentialCommitment);
    });

    it("verifyCredentialProof() full gas — 10 calls", async function () {
        const proofStruct = { a: pA, b: pB, c: pC };
        const gasReadings = [];

        for (let i = 0; i < 10; i++) {
            // Each call needs a unique nullifier — re-use by deploying fresh contract
            const ZKV = await ethers.getContractFactory("ZKVerifier");
            const fresh = await ZKV.deploy(groth16Verifier.address);
            await fresh.deployed();
            await fresh.addTrustedIssuer(issuerPublicKey);
            await fresh.registerCredential(issuerPublicKey, credentialCommitment);

            const gas = await fresh.connect(user).estimateGas.verifyCredentialProof(
                proofStruct, inputs);
            gasReadings.push(Number(gas));
        }

        const mean = Math.round(gasReadings.reduce((a, b) => a + b, 0) / gasReadings.length);
        const min  = Math.min(...gasReadings);
        const max  = Math.max(...gasReadings);

        console.log(`\n  verifyCredentialProof() full gas (10 estimateGas calls):`);
        gasReadings.forEach((g, i) =>
            console.log(`    Run ${i+1}: ${g.toLocaleString()} gas`));
        console.log(`  Mean: ${mean.toLocaleString()} | Min: ${min.toLocaleString()} | Max: ${max.toLocaleString()}`);
        console.log(`  Overhead vs Groth16Verifier.verifyProof(): +${(mean - 396197).toLocaleString()} gas`);

        expect(mean).to.be.lessThan(600000);
    });

    it("banUser() gas", async function () {
        const gas = await zkVerifier.estimateGas.banUser(scopeNullifier);
        console.log(`\n  banUser():               ${Number(gas).toLocaleString()} gas`);
    });
});
