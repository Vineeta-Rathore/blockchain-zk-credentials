'use strict';
const crypto  = require('crypto');
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const fs   = require('fs');
const path = require('path');

const BN128_R = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const fieldElement = str => (BigInt('0x' + crypto.createHash('sha256').update(str).digest('hex')) % BN128_R).toString();
const toBigInt = v => typeof v === 'bigint' ? v : BigInt(v);

const BUILD = path.join(__dirname, '..', 'build', 'circuits');
const RUNS  = 50;

const CRED = {
    userSecret: fieldElement('user-private-secret-v1'),
    issuerPublicKey: fieldElement('did:journal3:social-platform'),
    schemaHash: fieldElement('SocialMediaIdentityCredential'),
    challenge: fieldElement('platform-session-challenge-2026'),
    nullifierSeed: fieldElement('user-nullifier-seed-v1'),
    credentialSalt: fieldElement('issuer-credential-salt-v1'),
    platformId: fieldElement('social-platform-scope-id-v1'),
    predicateThreshold: '18', predicateAttributeIndex: '0',
};

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const n = 8;
    const attrs = ['25','90','1','356','1','0','0','0'];
    const revealFlags = ['0','0','1','0','0','0','0','0'];
    const credentialCommitment = F.toString(poseidon([
        toBigInt(CRED.issuerPublicKey), toBigInt(CRED.credentialSalt), ...attrs.map(toBigInt)]));
    const input = {
        userSecret: CRED.userSecret, attributes: attrs, revealFlags,
        nullifierSeed: CRED.nullifierSeed, credentialSalt: CRED.credentialSalt,
        issuerPublicKey: CRED.issuerPublicKey, schemaHash: CRED.schemaHash,
        challenge: CRED.challenge, predicateThreshold: CRED.predicateThreshold,
        predicateAttributeIndex: CRED.predicateAttributeIndex,
        credentialCommitment, platformId: CRED.platformId,
    };

    const WASM = path.join(BUILD, 'credential_verification_js', 'credential_verification.wasm');
    const ZKEY = path.join(BUILD, 'credential_verification.zkey');

    console.log(`CredentialVerification(8) — ${RUNS} runs, saving raw samples`);

    const t0 = process.hrtime.bigint();
    const { publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const coldMs = Number(process.hrtime.bigint() - t0) / 1e6;

    if (publicSignals[0] !== '1') { console.error(`credentialValid=${publicSignals[0]}`); process.exit(1); }
    console.log(`credentialValid = 1 ✓  cold-start: ${coldMs.toFixed(1)} ms (excluded)`);

    const samples = [];
    for (let i = 0; i < RUNS - 1; i++) {
        const t = process.hrtime.bigint();
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const ms = parseFloat((Number(process.hrtime.bigint() - t) / 1e6).toFixed(3));
        samples.push(ms);
        process.stdout.write(`  Run ${String(i+2).padStart(2)}: ${ms.toFixed(1)} ms\n`);
    }

    const sorted = [...samples].sort((a, b) => a - b);
    const mean = samples.reduce((s, v) => s + v, 0) / samples.length;
    const stdDev = Math.sqrt(samples.reduce((s, v) => s + (v - mean) ** 2, 0) / samples.length);
    const pct = p => sorted[Math.min(Math.floor(sorted.length * p), sorted.length - 1)];

    const stats = {
        mean:   parseFloat(mean.toFixed(3)),
        stdDev: parseFloat(stdDev.toFixed(3)),
        p50:    parseFloat(pct(0.50).toFixed(3)),
        p95:    parseFloat(pct(0.95).toFixed(3)),
        min:    parseFloat(sorted[0].toFixed(3)),
        max:    parseFloat(sorted[sorted.length - 1].toFixed(3)),
        warmRuns: RUNS - 1,
    };

    console.log(`\nWarm (n=49): mean=${stats.mean} ms, σ=${stats.stdDev} ms, p50=${stats.p50} ms, p95=${stats.p95} ms`);
    console.log(`min=${stats.min} ms, max=${stats.max} ms`);

    const out = {
        generated: new Date().toISOString().slice(0, 10),
        circuit: 'CredentialVerification(8)',
        totalRuns: RUNS,
        coldStartMs: parseFloat(coldMs.toFixed(3)),
        warmSamples: samples,
        stats,
    };

    const outFile = path.join(BUILD, 'latency_raw_n8.json');
    fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
    console.log(`\nRaw samples saved to: ${outFile}`);
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
