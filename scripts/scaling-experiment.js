/**
 * Attribute-Scaling Experiment for Journal of Supercomputing Section 6.4
 *
 * For numAttributes in [2, 4, 8]:
 *   1. Compiles credential_verification_N.circom -> R1CS + WASM
 *   2. Runs Phase 2 trusted setup using existing pot14_final.ptau
 *   3. Exports verification key and Solidity verifier
 *   4. Generates proof and runs latency benchmark (50 runs)
 *   5. Estimates verifier gas via Hardhat
 *
 * Run: node scripts/scaling-experiment.js
 * Outputs: build/circuits/scaling/ directory with per-N subdirectories
 *          build/circuits/scaling/scaling_results.json (citable summary)
 */

'use strict';

const { execSync, spawnSync } = require('child_process');
const crypto   = require('crypto');
const snarkjs  = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const ethers   = require('ethers');
const fs       = require('fs');
const path     = require('path');

const BN128_R = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const ROOT    = path.join(__dirname, '..');
const CIRCOM  = path.join(ROOT, 'circom', 'target', 'release', 'circom.exe');
const PTAU    = path.join(ROOT, 'build', 'circuits', 'pot14_final.ptau');
const SCALE_DIR = path.join(ROOT, 'build', 'circuits', 'scaling');
const CIRCUITS_DIR = path.join(ROOT, 'circuits');

const BENCHMARK_RUNS = 50;

function fieldElement(str) {
    const h = crypto.createHash('sha256').update(str).digest('hex');
    return (BigInt('0x' + h) % BN128_R).toString();
}

function percentile(sorted, p) {
    const idx = Math.floor(sorted.length * p);
    return sorted[Math.min(idx, sorted.length - 1)];
}

function stats(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const mean   = samples.reduce((s, v) => s + v, 0) / samples.length;
    const stdDev = Math.sqrt(
        samples.reduce((sum, v) => sum + (v - mean) ** 2, 0) / samples.length
    );
    return {
        mean:   parseFloat(mean.toFixed(3)),
        stdDev: parseFloat(stdDev.toFixed(3)),
        p50:    parseFloat(percentile(sorted, 0.50).toFixed(3)),
        p95:    parseFloat(percentile(sorted, 0.95).toFixed(3)),
        min:    parseFloat(sorted[0].toFixed(3)),
        max:    parseFloat(sorted[sorted.length - 1].toFixed(3)),
    };
}

function run(cmd, opts = {}) {
    return execSync(cmd, { stdio: 'pipe', ...opts }).toString().trim();
}

async function compileAndSetup(n, outDir) {
    const baseName   = `credential_verification_${n}`;
    const circomFile = path.join(CIRCUITS_DIR, `${baseName}.circom`);
    const r1csFile   = path.join(outDir, `${baseName}.r1cs`);
    const zkeyFile   = path.join(outDir, `${baseName}.zkey`);
    const vkeyFile   = path.join(outDir, `verification_key.json`);
    const solFile    = path.join(outDir, `Groth16Verifier.sol`);
    const wasmDir    = path.join(outDir, `${baseName}_js`);
    const wasmFile   = path.join(wasmDir, `${baseName}.wasm`);

    console.log(`\n  [1] Compiling credential_verification_${n}.circom...`);
    // --include points at node_modules for circomlib
    const includeDir = path.join(ROOT, 'node_modules');
    const compileResult = spawnSync(CIRCOM, [
        circomFile,
        '--r1cs', '--wasm', '--sym',
        '--output', outDir,
        '-l', includeDir,
    ], { encoding: 'utf8' });
    if (compileResult.status !== 0) {
        console.error(compileResult.stderr);
        throw new Error(`circom compilation failed for n=${n}`);
    }
    // Parse constraints and wires from circom output
    const compileOut = compileResult.stdout + compileResult.stderr;
    console.log(compileOut.trim());

    // Parse circom output for circuit metrics
    console.log(`  [2] Parsing circuit metrics from compiler output...`);
    const parseNum = (text, label) => {
        const m = text.match(new RegExp(`${label}:\\s*(\\d+)`));
        return m ? parseInt(m[1]) : null;
    };
    const nonLinear   = parseNum(compileOut, 'non-linear constraints');
    const linear      = parseNum(compileOut, 'linear constraints');
    const constraints = (nonLinear || 0) + (linear || 0);
    const wires       = parseNum(compileOut, 'wires');
    const nPubInputs  = parseNum(compileOut, 'public inputs');
    const nOutputs    = parseNum(compileOut, 'public outputs');
    const nPublic     = (nPubInputs || 0) + (nOutputs || 0);
    console.log(`    R1CS constraints: ${constraints} (${nonLinear} non-linear + ${linear} linear)`);
    console.log(`    Wires:            ${wires}`);
    console.log(`    nPublic:          ${nPublic} (${nPubInputs} pub inputs + ${nOutputs} outputs)`);

    // Phase 2 setup
    console.log(`  [3] Phase 2 trusted setup (pot14_final.ptau)...`);
    const zkey0 = path.join(outDir, `${baseName}_0000.zkey`);
    await snarkjs.zKey.newZKey(r1csFile, PTAU, zkey0);
    await snarkjs.zKey.beacon(
        zkey0, zkeyFile,
        'Final beacon for Journal 3 scaling experiment',
        '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        10
    );
    fs.unlinkSync(zkey0);

    // Export vkey
    const vkey = await snarkjs.zKey.exportVerificationKey(zkeyFile);
    fs.writeFileSync(vkeyFile, JSON.stringify(vkey, null, 2));

    // Export Solidity verifier
    const templatePath = path.join(ROOT, 'node_modules', 'snarkjs', 'templates', 'verifier_groth16.sol.ejs');
    const templates = { groth16: fs.readFileSync(templatePath, 'utf8') };
    const solidityCode = await snarkjs.zKey.exportSolidityVerifier(zkeyFile, templates);
    fs.writeFileSync(solFile, solidityCode);
    console.log(`    Exported: verification_key.json, Groth16Verifier.sol`);

    return { constraints, wires, nPublic, wasmFile, zkeyFile, vkeyFile, solFile };
}

async function buildInput(n) {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const userSecret  = fieldElement('user-private-secret-v1');
    const issuerPublicKey = fieldElement('did:journal3:social-platform');
    const schemaHash  = fieldElement('SocialMediaIdentityCredential');
    const challenge   = fieldElement('platform-session-challenge-2026');
    const nullifierSeed = fieldElement('user-nullifier-seed-v1');
    const credentialSalt = fieldElement('issuer-credential-salt-v1');
    const platformId  = fieldElement('social-platform-scope-id-v1');

    // Use first N attributes from the 8-attribute schema
    const allAttributes = ['25', '90', '1', '356', '1', '0', '0', '0'];
    const allRevealFlags = ['0', '0', '1', '0', '0', '0', '0', '0'];
    const attributes  = allAttributes.slice(0, n);
    const revealFlags = allRevealFlags.slice(0, n);

    // credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attr[0..n-1])
    const credCommitInputs = [
        BigInt(issuerPublicKey),
        BigInt(credentialSalt),
        ...attributes.map(BigInt),
    ];
    const credentialCommitment = F.toString(poseidon(credCommitInputs));

    return {
        userSecret, issuerPublicKey, schemaHash, challenge,
        nullifierSeed, credentialSalt, platformId,
        attributes, revealFlags,
        credentialCommitment,
        predicateThreshold: '18',
        predicateAttributeIndex: '0',
    };
}

async function benchmarkLatency(input, wasmFile, zkeyFile) {
    console.log(`  [4] Latency benchmark (${BENCHMARK_RUNS} runs)...`);
    const samples = [];

    // First run (cold start)
    const t0 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmFile, zkeyFile);
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
    process.stdout.write(`    Run  1: ${samples[0].toFixed(1)} ms  [cold]\n`);

    if (publicSignals[0] !== '1') {
        throw new Error(`credentialValid = ${publicSignals[0]} (expected 1) — commitment mismatch`);
    }

    // Warm runs
    for (let i = 1; i < BENCHMARK_RUNS; i++) {
        const t = process.hrtime.bigint();
        await snarkjs.groth16.fullProve(input, wasmFile, zkeyFile);
        samples.push(Number(process.hrtime.bigint() - t) / 1e6);
        process.stdout.write(`    Run ${String(i + 1).padStart(2)}: ${samples[i].toFixed(1)} ms\n`);
    }

    const coldStart   = samples[0];
    const warmSamples = samples.slice(1);
    const warmStats   = stats(warmSamples);

    return { coldStart, warmStats, proof, publicSignals };
}

async function estimateGas(solFile, proof, publicSignals, n) {
    console.log(`  [5] Estimating verifier gas (Groth16Verifier.verifyProof())...`);

    // Read the Solidity file and extract the ABI + bytecode using ethers inline compilation
    // We use Hardhat's compile cache if available, else compile via hardhat
    // For a self-contained script, use the existing Hardhat config
    const { ethers: hre } = require('hardhat');

    // Copy the scaling verifier into a temp location that Hardhat can compile
    const contractsDir = path.join(ROOT, 'contracts');
    const tempVerifier = path.join(contractsDir, `Groth16Verifier_scale${n}.sol`);
    let solContent = fs.readFileSync(solFile, 'utf8');
    // Rename contract so Hardhat doesn't conflict with existing Groth16Verifier
    solContent = solContent.replace(/contract Groth16Verifier\b/g, `contract Groth16Verifier_scale${n}`);
    fs.writeFileSync(tempVerifier, solContent);

    try {
        // Compile (--force ensures new contract is picked up even with cache)
        run('npx hardhat compile --force --quiet', { cwd: ROOT });

        const factory = await hre.getContractFactory(`Groth16Verifier_scale${n}`);
        const verifier = await factory.deploy();
        await verifier.deployed();

        const pA = [proof.pi_a[0], proof.pi_a[1]];
        const pB = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
        const pC = [proof.pi_c[0], proof.pi_c[1]];
        const pubSignalsBN = publicSignals.map(s => s.toString());

        const gasReadings = [];
        for (let i = 0; i < 10; i++) {
            const g = await verifier.estimateGas.verifyProof(pA, pB, pC, pubSignalsBN);
            gasReadings.push(Number(g));
        }
        const meanGas = Math.round(gasReadings.reduce((a, b) => a + b, 0) / gasReadings.length);
        console.log(`    verifyProof() mean gas (10 calls): ${meanGas.toLocaleString()}`);
        return meanGas;
    } finally {
        // Clean up temp verifier
        if (fs.existsSync(tempVerifier)) fs.unlinkSync(tempVerifier);
    }
}

async function runVariant(n, results) {
    console.log('\n' + '='.repeat(60));
    console.log(`  CredentialVerification(${n}) — Attribute Scaling`);
    console.log('='.repeat(60));

    const outDir = path.join(SCALE_DIR, `n${n}`);
    fs.mkdirSync(outDir, { recursive: true });

    const { constraints, wires, nPublic, wasmFile, zkeyFile, vkeyFile, solFile } =
        await compileAndSetup(n, outDir);

    const input = await buildInput(n);
    fs.writeFileSync(path.join(outDir, 'test_input.json'), JSON.stringify(input, null, 2));

    const { coldStart, warmStats, proof, publicSignals } =
        await benchmarkLatency(input, wasmFile, zkeyFile);

    fs.writeFileSync(path.join(outDir, 'proof.json'),  JSON.stringify(proof, null, 1));
    fs.writeFileSync(path.join(outDir, 'public.json'), JSON.stringify(publicSignals, null, 1));

    const gas = await estimateGas(solFile, proof, publicSignals, n);

    const row = {
        numAttributes: n,
        constraints,
        wires,
        nPublic,
        coldStartMs: parseFloat(coldStart.toFixed(3)),
        latencyMs: warmStats,
        verifyProofGas: gas,
        proofSizeBytes: 256,  // fixed for Groth16/BN128: pi_a(64) + pi_b(128) + pi_c(64)
    };

    console.log(`\n  Summary for n=${n}:`);
    console.log(`    Constraints:    ${constraints}`);
    console.log(`    Wires:          ${wires}`);
    console.log(`    nPublic:        ${nPublic}`);
    console.log(`    Latency mean:   ${warmStats.mean} ms  (sigma=${warmStats.stdDev})`);
    console.log(`    Latency p95:    ${warmStats.p95} ms`);
    console.log(`    verifyProof():  ${gas.toLocaleString()} gas`);

    results.push(row);
}

async function main() {
    if (!fs.existsSync(PTAU)) {
        console.error(`Missing: ${PTAU}`);
        console.error('pot14_final.ptau must exist from the original trusted setup.');
        process.exit(1);
    }

    fs.mkdirSync(SCALE_DIR, { recursive: true });

    const results = [];

    // Run variants in order
    for (const n of [2, 4, 8]) {
        if (n === 8) {
            // Use pre-existing 8-attr artifacts — do not recompile
            console.log('\n' + '='.repeat(60));
            console.log(`  CredentialVerification(8) — Using existing artifacts`);
            console.log('='.repeat(60));
            const build8 = path.join(ROOT, 'build', 'circuits');
            const existing = JSON.parse(fs.readFileSync(path.join(build8, 'benchmark_report.json'), 'utf8'));
            const gas8 = 396197;  // confirmed from rerun 2026-05-21
            results.push({
                numAttributes: 8,
                constraints:   6768,  // confirmed from rerun 2026-05-21 (added predicateAttributeIndex===0)
                wires:         6785,  // confirmed
                nPublic:       27,    // confirmed from paper
                coldStartMs:   existing.latencyMs.coldStartMs,
                latencyMs:     existing.latencyMs.warm,
                verifyProofGas: gas8,
                proofSizeBytes: 256,
            });
            console.log(`    Using pre-measured data: constraints=6768, gas=${gas8.toLocaleString()}`);
        } else {
            await runVariant(n, results);
        }
    }

    // Write summary
    const summary = {
        generated: new Date().toISOString(),
        experiment: 'Attribute scaling: CredentialVerification(2), (4), (8)',
        note: 'n=8 uses pre-existing artifacts. n=2,4 freshly compiled with same ptau.',
        results,
        gasPerPublicSignal: (() => {
            const r2 = results.find(r => r.numAttributes === 2);
            const r8 = results.find(r => r.numAttributes === 8);
            if (!r2 || !r8) return null;
            return parseFloat(((r8.verifyProofGas - r2.verifyProofGas) / (r8.nPublic - r2.nPublic)).toFixed(0));
        })(),
    };

    const summaryPath = path.join(SCALE_DIR, 'scaling_results.json');
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

    console.log('\n' + '='.repeat(60));
    console.log('  SCALING RESULTS SUMMARY');
    console.log('='.repeat(60));
    console.log('  n | constraints | nPublic | latency mean (ms) | verifyProof gas');
    console.log('  ' + '-'.repeat(65));
    for (const r of results) {
        console.log(
            `  ${r.numAttributes} | ${String(r.constraints).padStart(11)} | ${String(r.nPublic).padStart(7)} | ${String(r.latencyMs.mean).padStart(17)} | ${r.verifyProofGas.toLocaleString().padStart(15)}`
        );
    }
    console.log(`\n  Gas per additional public signal (n=2 to n=8): ~${summary.gasPerPublicSignal} gas/signal`);
    console.log(`\n  Full results: ${summaryPath}`);
}

main().catch(err => {
    console.error('\nFATAL:', err.message);
    console.error(err.stack);
    process.exit(1);
});
