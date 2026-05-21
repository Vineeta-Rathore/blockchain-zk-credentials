/**
 * @journal JOURNAL 3 — Privacy-Preserving ZK Credential Verification (in progress)
 *
 * Application domain: Social Media Identity Management
 *   Extends Journal 2 (DID + VC + on-chain revocation) by adding a ZK privacy
 *   layer. Users prove properties of their social media identity credential
 *   without revealing the underlying attribute values.
 *
 * Purpose: Generate a semantically correct SocialMediaIdentityCredential
 *   test_input.json where credentialCommitment = Poseidon(issuerPublicKey,
 *   credentialSalt, attributes[0..7]), producing credentialValid = 1 in the proof. Then run a
 *   latency benchmark (50 runs, warm stats reported separately).
 *
 * Option A fix: credentialHash (private) replaced by credentialCommitment (PUBLIC).
 * Issue 2 fix: scopeNullifier = Poseidon(userSecret, platformId) added as stable
 *   per-(user, platform) output. platformId added as public input.
 *   nPublic = 27 (was 25). pubSignals layout:
 *     [0-19]: credentialValid, nullifier, attrCommitments[8], revealedValues[8],
 *             predicateSatisfied, scopeNullifier
 *     [20-26]: issuerPublicKey, schemaHash, challenge, predicateThreshold,
 *              predicateAttributeIndex, credentialCommitment, platformId
 *
 * Credential schema — SocialMediaIdentityCredential (8 attributes):
 *   attr[0] age            — COPPA/GDPR compliance: prove age >= 18 without
 *                            the platform storing the exact birthdate
 *   attr[1] accountAgeDays — Anti-spam: prove account is established (>= 30 days)
 *                            without revealing creation date
 *   attr[2] verifiedHuman  — Sybil resistance: 1 = passed liveness check, 0 = not
 *                            Selectively disclosed to prove bot-resistance
 *   attr[3] countryCode    — Geo-gating: reveal only when required for compliance
 *   attr[4] contentTier    — Creator status: 0=standard, 1=creator, 2=verified
 *   attr[5] reserved       — Future: follower tier, moderation score, etc.
 *   attr[6] reserved
 *   attr[7] reserved
 *
 * Three social media ZK use cases proved by this circuit:
 *   1. Age-gated access  — predicateSatisfied proves age >= 18 (COPPA/GDPR)
 *                          without revealing exact age
 *   2. Sybil resistance  — verifiedHuman(attr[2]) selectively disclosed;
 *                          nullifier ensures one credential = one platform session
 *   3. Ban-evasion proof — scopeNullifier = Poseidon(userSecret, platformId) is
 *                          stable across sessions; ZKVerifier.sol's bannedScopeNullifiers
 *                          mapping blocks any future proof from a banned user on that platform
 *
 * Requires: circomlibjs (Poseidon), snarkjs (groth16)
 * Run: node scripts/generate-test-input.js
 *
 * Outputs:
 *   build/circuits/test_input.json     — social media credential input
 *   build/circuits/proof.json          — Groth16 proof (credentialValid = 1)
 *   build/circuits/public.json         — 27 public signals
 *   build/circuits/benchmark_report.json — all citable metrics
 */

'use strict';

const crypto   = require('crypto');
const snarkjs  = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const fs   = require('fs');
const path = require('path');

// BN128 scalar field size — all field elements must be reduced mod this
const BN128_R = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// Derive a deterministic field element from a string (SHA-256 mod BN128_R)
function fieldElement(str) {
    const h = crypto.createHash('sha256').update(str).digest('hex');
    return (BigInt('0x' + h) % BN128_R).toString();
}

// ── Paths ──────────────────────────────────────────────────────────────────
const BUILD   = path.join(__dirname, '..', 'build', 'circuits');
const WASM    = path.join(BUILD, 'credential_verification_js', 'credential_verification.wasm');
const ZKEY    = path.join(BUILD, 'credential_verification.zkey');
const VKEY    = path.join(BUILD, 'verification_key.json');
const IN_FILE  = path.join(BUILD, 'test_input.json');
const PROOF    = path.join(BUILD, 'proof.json');
const PUB      = path.join(BUILD, 'public.json');

// ── SocialMediaIdentityCredential — field-element values ──────────────────
//
//   issuerPublicKey : field element of "did:journal3:social-platform"
//                     (the platform acting as the trusted identity issuer)
//   schemaHash      : field element of "SocialMediaIdentityCredential"
//                     (credential type identifier, public — verifier knows the schema)
//   challenge       : field element of "platform-session-challenge-2026"
//                     (per-session random nonce issued by the platform verifier)
//   nullifierSeed   : field element of "user-nullifier-seed-v1"
//                     (per-user secret seed, private — prevents nullifier linkage)
//   userSecret      : private random value binding user to credential
//
// These are computed at runtime via fieldElement() so they are deterministic
// across machines and reproducible for the paper's appendix.
//
// Attribute values (field elements — small integers are valid field elements):
//   attr[0] age            = 25   (proves >= 18 via predicate; value stays private)
//   attr[1] accountAgeDays = 90   (proves >= 30 via predicate; value stays private)
//   attr[2] verifiedHuman  = 1    (selectively disclosed: proves bot-resistance)
//   attr[3] countryCode    = 356  (India, ISO 3166-1 numeric; hidden by default)
//   attr[4] contentTier    = 1    (creator tier; hidden by default)
//   attr[5..7]             = 0    (reserved)

const CREDENTIAL = {
    userSecret:            fieldElement('user-private-secret-v1'),
    issuerPublicKey:       fieldElement('did:journal3:social-platform'),
    schemaHash:            fieldElement('SocialMediaIdentityCredential'),
    challenge:             fieldElement('platform-session-challenge-2026'),
    nullifierSeed:         fieldElement('user-nullifier-seed-v1'),
    credentialSalt:        fieldElement('issuer-credential-salt-v1'),
    // ^ high-entropy issuer-generated nonce; prevents offline dictionary attacks on
    //   credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attr[0..7])
    platformId:            fieldElement('social-platform-scope-id-v1'),
    // ^ stable platform identifier — bound into scopeNullifier for ban prevention
    attributes:            ['25', '90', '1', '356', '1', '0', '0', '0'],
    //                       age  acctAge  human  country  tier  res  res  res
    revealFlags:           ['0',  '0',    '1',   '0',     '0',  '0', '0', '0'],
    // Only verifiedHuman (attr[2]) is revealed — age proved by predicate, not value
    predicateThreshold:    '18',        // platform requires age >= 18 (COPPA/GDPR)
    predicateAttributeIndex: '0',       // predicate applies to attr[0] = age
};

const BENCHMARK_RUNS = 50;   // 1 cold-start + 49 warm runs

// ── Helpers ────────────────────────────────────────────────────────────────

function toBigInt(v) {
    return typeof v === 'bigint' ? v : BigInt(v);
}

function percentile(sorted, p) {
    const idx = Math.floor(sorted.length * p);
    return sorted[Math.min(idx, sorted.length - 1)];
}

function stats(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const mean   = samples.reduce((s, v) => s + v, 0) / samples.length;
    return {
        mean:  mean.toFixed(3),
        p50:   percentile(sorted, 0.50).toFixed(3),
        p95:   percentile(sorted, 0.95).toFixed(3),
        min:   sorted[0].toFixed(3),
        max:   sorted[sorted.length - 1].toFixed(3),
    };
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
    // 1. Check circuit build artifacts exist
    for (const f of [WASM, ZKEY, VKEY]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f}`);
            console.error('Run the trusted setup first (see JOURNALS.md Step 2-3).');
            process.exit(1);
        }
    }

    console.log('='.repeat(60));
    console.log('  Journal 3 — ZK Test Input Generator + Latency Benchmark');
    console.log('='.repeat(60));

    // 2. Build Poseidon and compute:
    //    credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attributes[8])  [CB2 fix]
    //    scopeNullifier       = Poseidon(userSecret, platformId)                          [Issue 2 fix]
    console.log('\n[1/4] Computing Poseidon hashes (credentialCommitment + scopeNullifier)...');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // credentialCommitment: Poseidon(10) with inputs [issuerPublicKey, credentialSalt, attr0..7]
    // credentialSalt is a high-entropy issuer-generated nonce; prevents offline dictionary attacks.
    const credCommitInputs = [
        toBigInt(CREDENTIAL.issuerPublicKey),
        toBigInt(CREDENTIAL.credentialSalt),
        ...CREDENTIAL.attributes.map(toBigInt),
    ];
    const credentialCommitment = F.toString(poseidon(credCommitInputs));

    // scopeNullifier: Poseidon(2) with inputs [userSecret, platformId]
    const scopeInputs = [
        toBigInt(CREDENTIAL.userSecret),
        toBigInt(CREDENTIAL.platformId),
    ];
    const expectedScopeNullifier = F.toString(poseidon(scopeInputs));

    console.log(`    Schema:              SocialMediaIdentityCredential`);
    console.log(`    Issuer:              did:journal3:social-platform`);
    console.log(`    issuerPublicKey:     ${CREDENTIAL.issuerPublicKey.slice(0, 20)}...`);
    console.log(`    platformId:          ${CREDENTIAL.platformId.slice(0, 20)}...`);
    console.log(`    Attributes:          [age=25, acctAge=90, human=1, country=356, tier=1, 0, 0, 0]`);
    console.log(`    RevealFlags:         [0, 0, 1, 0, 0, 0, 0, 0]  (only verifiedHuman revealed)`);
    console.log(`    Predicate:           age(attr[0]=25) >= 18  (COPPA/GDPR compliance)`);
    console.log(`    credentialCommitment: ${credentialCommitment}`);
    console.log(`    scopeNullifier:       ${expectedScopeNullifier}`);
    console.log('    (credentialValid should = 1 if circuit recomputes same commitment)');

    // 3. Write test_input.json — credentialSalt PRIVATE (CB2), credentialCommitment PUBLIC, platformId PUBLIC
    const input = {
        userSecret:              CREDENTIAL.userSecret,
        attributes:              CREDENTIAL.attributes,
        revealFlags:             CREDENTIAL.revealFlags,
        nullifierSeed:           CREDENTIAL.nullifierSeed,
        credentialSalt:          CREDENTIAL.credentialSalt,   // private — prevents dictionary attack
        issuerPublicKey:         CREDENTIAL.issuerPublicKey,
        schemaHash:              CREDENTIAL.schemaHash,
        challenge:               CREDENTIAL.challenge,
        predicateThreshold:      CREDENTIAL.predicateThreshold,
        predicateAttributeIndex: CREDENTIAL.predicateAttributeIndex,
        credentialCommitment,
        platformId:              CREDENTIAL.platformId,
    };

    fs.writeFileSync(IN_FILE, JSON.stringify(input, null, 2));
    console.log(`\n[2/4] Written: ${IN_FILE}`);

    // 4. Generate one canonical proof (saved to disk for ZKVerifier.gas.test.js)
    console.log('\n[3/4] Generating canonical proof (credentialValid = 1)...');
    const t0 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const firstMs = Number(process.hrtime.bigint() - t0) / 1e6;

    // Verify credentialValid = 1 in public signals (index 0 per circuit output order)
    const credentialValidSignal = publicSignals[0];
    if (credentialValidSignal !== '1') {
        console.error(`\n  ERROR: credentialValid = ${credentialValidSignal} (expected 1).`);
        console.error('  credentialCommitment mismatch — check Poseidon input ordering.');
        console.error('  Circuit: Poseidon(issuerPublicKey, attr[0..7]) must match pubSignals[25].');
        process.exit(1);
    } else {
        console.log(`    credentialValid  = ${credentialValidSignal} ✓`);
    }

    // pubSignals layout after Issue 2 fix (nPublic = 27):
    //   [0]    credentialValid
    //   [1]    nullifier
    //   [2-9]  attributeCommitments[8]
    //   [10-17] revealedValues[8]
    //   [18]   predicateSatisfied
    //   [19]   scopeNullifier       ← NEW
    //   [20]   issuerPublicKey
    //   [21]   schemaHash
    //   [22]   challenge
    //   [23]   predicateThreshold
    //   [24]   predicateAttributeIndex
    //   [25]   credentialCommitment  (was [24] before Issue 2)
    //   [26]   platformId            ← NEW

    // Verify scopeNullifier at pubSignals[19]
    console.log(`    scopeNullifier (pubSignals[19]) = ${publicSignals[19].slice(0,20)}...`);
    if (publicSignals[19] !== expectedScopeNullifier) {
        console.error('  ERROR: pubSignals[19] does not match computed scopeNullifier!');
        process.exit(1);
    }
    console.log(`    pubSignals[19] matches computed scopeNullifier ✓`);

    // Verify credentialCommitment at pubSignals[25]
    console.log(`    credentialCommitment (pubSignals[25]) = ${publicSignals[25].slice(0,20)}...`);
    if (publicSignals[25] !== credentialCommitment) {
        console.error('  ERROR: pubSignals[25] does not match computed credentialCommitment!');
        process.exit(1);
    }
    console.log(`    pubSignals[25] matches computed commitment ✓`);

    // Verify platformId at pubSignals[26]
    if (publicSignals[26] !== CREDENTIAL.platformId) {
        console.error('  ERROR: pubSignals[26] does not match platformId!');
        process.exit(1);
    }
    console.log(`    pubSignals[26] matches platformId ✓`);

    const predicateSig = publicSignals[18];
    console.log(`    predicateSatisfied = ${predicateSig} (age ${CREDENTIAL.attributes[0]} >= ${CREDENTIAL.predicateThreshold}: expect 1)`);
    console.log(`    nullifier          = ${publicSignals[1].slice(0, 20)}...`);
    console.log(`    First proof: ${firstMs.toFixed(1)} ms`);

    fs.writeFileSync(PROOF, JSON.stringify(proof, null, 1));
    fs.writeFileSync(PUB,   JSON.stringify(publicSignals, null, 1));
    console.log(`    Saved: ${PROOF}`);
    console.log(`    Saved: ${PUB}`);

    // 5. Off-chain verification sanity check
    const vkey = JSON.parse(fs.readFileSync(VKEY, 'utf8'));
    const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log(`    Off-chain snarkjs.groth16.verify: ${valid ? '✓ VALID' : '✗ INVALID'}`);
    if (!valid) {
        console.error('  Proof failed off-chain verification — trusted setup may be corrupt.');
        process.exit(1);
    }

    // 6. Latency benchmark
    console.log(`\n[4/4] Proof generation latency benchmark (${BENCHMARK_RUNS} runs)...`);
    const samples = [firstMs]; // include the canonical proof time

    for (let i = 1; i < BENCHMARK_RUNS; i++) {
        const t = process.hrtime.bigint();
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        samples.push(Number(process.hrtime.bigint() - t) / 1e6);
        process.stdout.write(`    Run ${String(i + 1).padStart(2)}: ${samples[i].toFixed(1)} ms\n`);
    }

    // Separate cold-start (Run 1) from warm runs (Runs 2-N)
    const coldStart  = samples[0];
    const warmSamples = samples.slice(1);

    const sAll  = stats(samples);
    const sWarm = stats(warmSamples);

    // Standard deviation of warm runs
    const warmMean = warmSamples.reduce((a, b) => a + b, 0) / warmSamples.length;
    const stdDev = Math.sqrt(
        warmSamples.reduce((sum, v) => sum + (v - warmMean) ** 2, 0) / warmSamples.length
    ).toFixed(3);

    console.log('\n' + '─'.repeat(60));
    console.log('  Proof Generation Latency — All Runs');
    console.log('─'.repeat(60));
    console.log(`  Total runs:    ${BENCHMARK_RUNS} (1 cold-start + ${BENCHMARK_RUNS - 1} warm)`);
    console.log(`  Cold-start:    ${coldStart.toFixed(3)} ms  (Run 1 — WASM init, excluded from warm stats)`);
    console.log('─'.repeat(60));
    console.log('  Warm Runs (Runs 2–' + BENCHMARK_RUNS + ') — CITE THESE IN THE PAPER');
    console.log('─'.repeat(60));
    console.log(`  Mean:  ${sWarm.mean} ms`);
    console.log(`  StdDev:${stdDev} ms`);
    console.log(`  p50:   ${sWarm.p50} ms`);
    console.log(`  p95:   ${sWarm.p95} ms`);
    console.log(`  Min:   ${sWarm.min} ms`);
    console.log(`  Max:   ${sWarm.max} ms`);
    console.log('─'.repeat(60));
    console.log('  Gas cost measured separately in test/ZKVerifier.gas.test.js (npx hardhat test)');
    console.log('='.repeat(60));

    // 7. Write a latency report next to the proof artifacts
    const report = {
        generated: new Date().toISOString(),
        circuit: 'credential_verification(8)',
        applicationDomain: 'Social Media Identity Management',
        credentialSchema: 'SocialMediaIdentityCredential',
        issuer: 'did:journal3:social-platform',
        attributeSchema: {
            0: 'age (predicate: >= 18, value private — COPPA/GDPR)',
            1: 'accountAgeDays (predicate: >= 30, value private — anti-spam)',
            2: 'verifiedHuman (selectively disclosed — Sybil resistance)',
            3: 'countryCode (ISO 3166-1 numeric, hidden by default — geo-gating)',
            4: 'contentTier (0=standard, 1=creator, 2=verified, hidden)',
            5: 'reserved', 6: 'reserved', 7: 'reserved',
        },
        zkUseCases: [
            'Age-gated platform access (COPPA/GDPR): proves age>=18 without storing birthdate',
            'Sybil resistance: verifiedHuman attribute selectively disclosed',
            'Ban-evasion prevention: scopeNullifier=Poseidon(userSecret,platformId) stable per (user,platform)',
        ],
        curve: 'bn128',
        protocol: 'groth16',
        constraints: 6768,      // confirmed from rerun 2026-05-21 (predicateAttributeIndex===0 constraint)
        wires: null,
        privateInputs: 19,      // userSecret, nullifierSeed, credentialSalt, attributes[8], revealFlags[8]
        publicInputs: 7,        // issuerPublicKey, schemaHash, challenge, predicateThreshold,
                                // predicateAttributeIndex, credentialCommitment, platformId
        outputs: 20,            // credentialValid, nullifier, attrCommitments[8], revealedValues[8],
                                // predicateSatisfied, scopeNullifier
        nPublic: 27,            // = publicInputs(7) + outputs(20)
        credentialCommitment,
        scopeNullifier: expectedScopeNullifier,
        credentialValid: credentialValidSignal === '1',
        predicateSatisfied: predicateSig === '1',
        latencyMs: {
            totalRuns: BENCHMARK_RUNS,
            coldStartMs: parseFloat(coldStart.toFixed(3)),
            warmRuns: BENCHMARK_RUNS - 1,
            warm: {
                mean:   parseFloat(sWarm.mean),
                stdDev: parseFloat(stdDev),
                p50:    parseFloat(sWarm.p50),
                p95:    parseFloat(sWarm.p95),
                min:    parseFloat(sWarm.min),
                max:    parseFloat(sWarm.max),
            },
            all: {
                mean: parseFloat(sAll.mean),
                p95:  parseFloat(sAll.p95),
            },
        },
        gasVerifyProof: 396197,  // confirmed from test/ZKVerifier.gas.test.js (10 estimateGas calls, mean)
        note: 'gasVerifyProof confirmed by test/ZKVerifier.gas.test.js. ' +
              'Warm latency excludes Run 1 (WASM cold-start). nPublic=27. Rerun 2026-05-21.',
    };

    const reportPath = path.join(BUILD, 'benchmark_report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n  Full report saved: ${reportPath}`);
}

main().catch(err => {
    console.error('\nFATAL:', err.message);
    process.exit(1);
});
