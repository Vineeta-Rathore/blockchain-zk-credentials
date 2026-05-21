'use strict';

/*
 * Read and display benchmark results from build/circuits/benchmark_report.json.
 * Gas costs are read from the last Hardhat test run output.
 *
 * Usage:
 *   node scripts/generate-test-input.js   (generates benchmark_report.json)
 *   npx hardhat test test/ZKVerifier.gas.test.js
 *   node scripts/measure-metrics.js
 */

const fs   = require('fs');
const path = require('path');

const BUILD = path.join(__dirname, '..', 'build', 'circuits');
const REPORT = path.join(BUILD, 'benchmark_report.json');

function main() {
    if (!fs.existsSync(REPORT)) {
        console.error('benchmark_report.json not found.');
        console.error('Run node scripts/generate-test-input.js first.');
        process.exit(1);
    }

    const r = JSON.parse(fs.readFileSync(REPORT, 'utf8'));

    console.log('='.repeat(60));
    console.log('  CredentialVerification(8) - Benchmark Summary');
    console.log('='.repeat(60));

    console.log('\nCircuit');
    console.log(`  Constraints (R1CS): ${r.constraints}`);
    console.log(`  Wires:              ${r.wires}`);
    console.log(`  Private inputs:     ${r.privateInputs}`);
    console.log(`  Public inputs:      ${r.publicInputs}`);
    console.log(`  Outputs:            ${r.outputs}`);
    console.log(`  nPublic:            ${r.nPublic}`);
    console.log(`  Curve:              ${r.curve}`);
    console.log(`  Protocol:           ${r.protocol}`);

    if (r.latencyMs) {
        const w = r.latencyMs.warm;
        console.log('\nProof Generation Latency (warm runs, n=' + r.latencyMs.warmRuns + ')');
        console.log(`  Mean:       ${w.mean} ms`);
        console.log(`  Std dev:    ${w.stdDev} ms`);
        console.log(`  p50:        ${w.p50} ms`);
        console.log(`  p95:        ${w.p95} ms`);
        console.log(`  Min:        ${w.min} ms`);
        console.log(`  Max:        ${w.max} ms`);
        console.log(`  Cold-start: ${r.latencyMs.coldStartMs} ms (excluded)`);
    }

    if (r.gasVerifyProof) {
        console.log('\nGas Costs');
        console.log(`  verifyProof (Groth16Verifier):          ${r.gasVerifyProof}`);
        console.log(`  verifyCredentialProof (ZKVerifier):     ${r.gasVerifyCredentialProof || 'see test output'}`);
    } else {
        console.log('\nGas costs: run npx hardhat test test/ZKVerifier.gas.test.js');
    }

    console.log('\n  Report generated: ' + r.generated);
    console.log('='.repeat(60));
}

main();
