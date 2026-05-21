'use strict';
/**
 * Isolated latency benchmark for n=2 and n=4 scaling circuits.
 * Run with: node scripts/scaling-latency-2-4.js
 * (Not via hardhat run — avoids compilation overhead contaminating measurements.)
 */

const crypto  = require('crypto');
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const fs   = require('fs');
const path = require('path');

const BN128_R = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
function fieldElement(str) {
    const h = crypto.createHash('sha256').update(str).digest('hex');
    return (BigInt('0x' + h) % BN128_R).toString();
}

const BUILD = path.join(__dirname, '..', 'build', 'circuits');
const RUNS  = 50;

const CRED = {
    userSecret:              fieldElement('user-private-secret-v1'),
    issuerPublicKey:         fieldElement('did:journal3:social-platform'),
    schemaHash:              fieldElement('SocialMediaIdentityCredential'),
    challenge:               fieldElement('platform-session-challenge-2026'),
    nullifierSeed:           fieldElement('user-nullifier-seed-v1'),
    credentialSalt:          fieldElement('issuer-credential-salt-v1'),
    platformId:              fieldElement('social-platform-scope-id-v1'),
    predicateThreshold:      '18',
    predicateAttributeIndex: '0',
};

function toBigInt(v) { return typeof v === 'bigint' ? v : BigInt(v); }

function stats(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const mean = samples.reduce((s, v) => s + v, 0) / samples.length;
    const stdDev = Math.sqrt(
        samples.reduce((s, v) => s + (v - mean) ** 2, 0) / samples.length);
    const pct = p => sorted[Math.min(Math.floor(sorted.length * p), sorted.length - 1)];
    return {
        mean:   parseFloat(mean.toFixed(3)),
        stdDev: parseFloat(stdDev.toFixed(3)),
        p50:    parseFloat(pct(0.50).toFixed(3)),
        p95:    parseFloat(pct(0.95).toFixed(3)),
        min:    parseFloat(sorted[0].toFixed(3)),
        max:    parseFloat(sorted[sorted.length - 1].toFixed(3)),
    };
}

async function bench(n, poseidon) {
    const F = poseidon.F;
    const attrs = Array.from({length: n}, (_, i) =>
        ['25','90','1','356','1','0','0','0'][i] ?? '0');
    const revealFlags = Array.from({length: n}, (_, i) => i === 2 ? '1' : '0');
    const credentialCommitment = F.toString(poseidon([
        toBigInt(CRED.issuerPublicKey),
        toBigInt(CRED.credentialSalt),
        ...attrs.map(toBigInt),
    ]));

    const input = {
        userSecret: CRED.userSecret, attributes: attrs, revealFlags,
        nullifierSeed: CRED.nullifierSeed, credentialSalt: CRED.credentialSalt,
        issuerPublicKey: CRED.issuerPublicKey, schemaHash: CRED.schemaHash,
        challenge: CRED.challenge, predicateThreshold: CRED.predicateThreshold,
        predicateAttributeIndex: CRED.predicateAttributeIndex,
        credentialCommitment, platformId: CRED.platformId,
    };

    const sfx  = `_${n}`;
    const WASM = path.join(BUILD, `credential_verification${sfx}_js`,
                           `credential_verification${sfx}.wasm`);
    const ZKEY = path.join(BUILD, `credential_verification${sfx}.zkey`);

    console.log(`\n${'='.repeat(55)}`);
    console.log(`  CredentialVerification(${n}) — ${RUNS} runs`);
    console.log(`${'='.repeat(55)}`);

    const t0 = process.hrtime.bigint();
    const { publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const coldMs = Number(process.hrtime.bigint() - t0) / 1e6;

    if (publicSignals[0] !== '1') {
        console.error(`  ERROR: credentialValid=${publicSignals[0]}`); process.exit(1);
    }
    console.log(`  credentialValid = 1 ✓  cold-start: ${coldMs.toFixed(1)} ms  (excluded)`);

    const samples = [];
    for (let i = 0; i < RUNS - 1; i++) {
        const t = process.hrtime.bigint();
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const ms = Number(process.hrtime.bigint() - t) / 1e6;
        samples.push(ms);
        process.stdout.write(`  Run ${String(i+2).padStart(2)}: ${ms.toFixed(1)} ms\n`);
    }

    const s = stats(samples);
    console.log(`${'─'.repeat(55)}`);
    console.log(`  Warm runs (n=${RUNS-1}):`);
    console.log(`    Mean:   ${s.mean} ms`);
    console.log(`    StdDev: ${s.stdDev} ms`);
    console.log(`    p50:    ${s.p50} ms`);
    console.log(`    p95:    ${s.p95} ms`);
    console.log(`    Min:    ${s.min} ms`);
    console.log(`    Max:    ${s.max} ms`);
    return { coldMs, s };
}

async function main() {
    const poseidon = await buildPoseidon();

    const r2 = await bench(2, poseidon);
    const r4 = await bench(4, poseidon);

    // Update scaling_results.json with correct latency
    const scaleFile = path.join(BUILD, 'scaling', 'scaling_results.json');
    const data = JSON.parse(fs.readFileSync(scaleFile, 'utf8'));

    data.results[0].coldStartMs  = parseFloat(r2.coldMs.toFixed(3));
    data.results[0].latencyMs    = { ...r2.s, warmRuns: RUNS-1 };
    data.results[1].coldStartMs  = parseFloat(r4.coldMs.toFixed(3));
    data.results[1].latencyMs    = { ...r4.s, warmRuns: RUNS-1 };
    data.generated               = new Date().toISOString().slice(0, 10);

    fs.writeFileSync(scaleFile, JSON.stringify(data, null, 2));

    console.log('\n' + '='.repeat(55));
    console.log('  LATENCY SUMMARY (cite these in the paper)');
    console.log('='.repeat(55));
    data.results.forEach(r =>
        console.log(`  n=${r.numAttributes}: mean=${r.latencyMs.mean} ms, σ=${r.latencyMs.stdDev} ms, p95=${r.latencyMs.p95} ms`));
    console.log(`\n  Saved: ${scaleFile}`);
}

main().catch(e => { console.error('\nFATAL:', e.message); process.exit(1); });
