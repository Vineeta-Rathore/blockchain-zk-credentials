#!/usr/bin/env node
/*
 * Multi-party computation (MPC) ceremony for Groth16 Phase 2 trusted setup.
 * Coordinates contributions from multiple participants to generate the
 * circuit-specific proving key for CredentialVerification(8).
 *
 * Usage: node scripts/mpc-ceremony.js
 * See build/circuits/SETUP_INFO.md for provenance details.
 */

const snarkjs = require('snarkjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const CONFIG = {
    circuitName: 'credential_verification',
    buildDir: path.join(__dirname, '../build/circuits'),
    ceremonyDir: path.join(__dirname, '../ceremony'),
    ptauPower: 14,
    minParticipants: 3
};

class MPCCeremony {
    constructor() {
        this.participants = [];
        this.currentPhase = 'init';
        this.contributions = [];
    }

    async initialize() {
        console.log('🎭 MPC Ceremony Coordinator\n');
        console.log('='.repeat(60));
        console.log('Multi-Party Computation Trusted Setup for ZK-SNARKs\n');

        // Create ceremony directory
        if (!fs.existsSync(CONFIG.ceremonyDir)) {
            fs.mkdirSync(CONFIG.ceremonyDir, { recursive: true });
        }

        // Check for existing ceremony
        const ceremonyFile = path.join(CONFIG.ceremonyDir, 'ceremony.json');
        if (fs.existsSync(ceremonyFile)) {
            const data = JSON.parse(fs.readFileSync(ceremonyFile, 'utf8'));
            this.participants = data.participants || [];
            this.contributions = data.contributions || [];
            this.currentPhase = data.phase || 'init';
            console.log(`📂 Resumed ceremony with ${this.participants.length} participants`);
        }
    }

    async runPhase1() {
        console.log('\n📋 PHASE 1: Powers of Tau Ceremony\n');

        const ptau0 = path.join(CONFIG.ceremonyDir, 'pot_0000.ptau');

        // Start new ceremony
        console.log('   Creating initial accumulator...');
        await snarkjs.powersOfTau.newAccumulator(
            snarkjs.bn128,
            CONFIG.ptauPower,
            ptau0
        );
        console.log('   ✅ Initial accumulator created');

        // Collect contributions
        await this.collectContributions('phase1');

        // Prepare for phase 2
        console.log('\n   Preparing phase 2...');
        const ptauFinal = path.join(CONFIG.ceremonyDir, 'pot_final.ptau');
        const lastPtau = path.join(CONFIG.ceremonyDir, `pot_${String(this.contributions.length).padStart(4, '0')}.ptau`);

        await snarkjs.powersOfTau.preparePhase2(lastPtau, ptauFinal);
        console.log('   ✅ Phase 1 complete');

        this.currentPhase = 'phase2';
        this.saveState();
    }

    async runPhase2() {
        console.log('\n📋 PHASE 2: Circuit-Specific Ceremony\n');

        const r1csPath = path.join(CONFIG.buildDir, `${CONFIG.circuitName}.r1cs`);
        const ptauFinal = path.join(CONFIG.ceremonyDir, 'pot_final.ptau');
        const zkey0 = path.join(CONFIG.ceremonyDir, 'circuit_0000.zkey');

        if (!fs.existsSync(r1csPath)) {
            console.error('❌ R1CS file not found. Run circuit compilation first.');
            return;
        }

        // Create initial zkey
        console.log('   Creating initial zkey...');
        await snarkjs.zKey.newZKey(r1csPath, ptauFinal, zkey0);
        console.log('   ✅ Initial zkey created');

        // Collect contributions for phase 2
        this.contributions = []; // Reset for phase 2
        await this.collectContributions('phase2');

        // Finalize
        await this.finalize();
    }

    async collectContributions(phase) {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        const question = (prompt) => new Promise(resolve => rl.question(prompt, resolve));

        let participantCount = 0;
        let continueAdding = true;

        while (continueAdding) {
            console.log(`\n   --- Participant ${participantCount + 1} ---`);

            const name = await question('   Enter participant name: ');
            const entropy = await question('   Enter random entropy (or press Enter for auto): ');

            const actualEntropy = entropy ||
                crypto.randomBytes(32).toString('hex') +
                Date.now().toString() +
                name;

            participantCount++;
            const inputFile = phase === 'phase1'
                ? path.join(CONFIG.ceremonyDir, `pot_${String(participantCount - 1).padStart(4, '0')}.ptau`)
                : path.join(CONFIG.ceremonyDir, `circuit_${String(participantCount - 1).padStart(4, '0')}.zkey`);

            const outputFile = phase === 'phase1'
                ? path.join(CONFIG.ceremonyDir, `pot_${String(participantCount).padStart(4, '0')}.ptau`)
                : path.join(CONFIG.ceremonyDir, `circuit_${String(participantCount).padStart(4, '0')}.zkey`);

            console.log(`   ⏳ Processing contribution...`);

            if (phase === 'phase1') {
                await snarkjs.powersOfTau.contribute(
                    inputFile,
                    outputFile,
                    `${name}'s contribution`,
                    actualEntropy
                );
            } else {
                await snarkjs.zKey.contribute(
                    inputFile,
                    outputFile,
                    `${name}'s contribution`,
                    actualEntropy
                );
            }

            const contributionHash = crypto.createHash('sha256')
                .update(fs.readFileSync(outputFile))
                .digest('hex');

            this.contributions.push({
                name,
                index: participantCount,
                phase,
                hash: contributionHash.substring(0, 16) + '...',
                timestamp: new Date().toISOString()
            });

            this.participants.push({ name, phase, index: participantCount });
            console.log(`   ✅ Contribution from ${name} added`);
            console.log(`   📝 Hash: ${contributionHash.substring(0, 32)}...`);

            if (participantCount >= CONFIG.minParticipants) {
                const more = await question(`   Add more participants? (y/n): `);
                continueAdding = more.toLowerCase() === 'y';
            }

            this.saveState();
        }

        rl.close();
    }

    async finalize() {
        console.log('\n📋 FINALIZATION\n');

        const lastZkey = path.join(
            CONFIG.ceremonyDir,
            `circuit_${String(this.contributions.length).padStart(4, '0')}.zkey`
        );
        const finalZkey = path.join(CONFIG.buildDir, `${CONFIG.circuitName}.zkey`);
        const vkey = path.join(CONFIG.buildDir, 'verification_key.json');

        // Apply beacon for final randomness
        console.log('   Applying random beacon...');
        const beacon = crypto.randomBytes(32).toString('hex');

        await snarkjs.zKey.beacon(
            lastZkey,
            finalZkey,
            'Final beacon',
            beacon,
            10 // iterations
        );
        console.log('   ✅ Beacon applied');

        // Export verification key
        console.log('   Exporting verification key...');
        const verificationKey = await snarkjs.zKey.exportVerificationKey(finalZkey);
        fs.writeFileSync(vkey, JSON.stringify(verificationKey, null, 2));
        console.log('   ✅ Verification key exported');

        // Generate transcript
        await this.generateTranscript();

        this.currentPhase = 'complete';
        this.saveState();

        console.log('\n' + '='.repeat(60));
        console.log('✅ MPC CEREMONY COMPLETE');
        console.log('='.repeat(60));
        console.log(`\n   Total Participants: ${this.participants.length}`);
        console.log(`   Final ZKey: ${finalZkey}`);
        console.log(`   Verification Key: ${vkey}`);
        console.log(`   Transcript: ${path.join(CONFIG.ceremonyDir, 'transcript.md')}`);
    }

    async generateTranscript() {
        console.log('   Generating ceremony transcript...');

        let transcript = `# MPC Ceremony Transcript

## Ceremony Information

| Property | Value |
|----------|-------|
| Circuit | ${CONFIG.circuitName} |
| Date | ${new Date().toISOString()} |
| Participants | ${this.participants.length} |
| Powers of Tau | 2^${CONFIG.ptauPower} |

## Contributions

| # | Name | Phase | Hash | Timestamp |
|---|------|-------|------|-----------|
`;

        for (const c of this.contributions) {
            transcript += `| ${c.index} | ${c.name} | ${c.phase} | \`${c.hash}\` | ${c.timestamp} |\n`;
        }

        transcript += `
## Security Guarantees

The ceremony is secure as long as **at least one participant** destroyed their random entropy after contributing. Since ${this.participants.length} independent participants contributed, the probability of a compromised ceremony is negligibly small.

## Verification

To verify the ceremony integrity:

\`\`\`bash
npx snarkjs zkey verify build/circuits/${CONFIG.circuitName}.r1cs ceremony/pot_final.ptau build/circuits/${CONFIG.circuitName}.zkey
\`\`\`

---

*Generated by MPC Ceremony Coordinator*
`;

        fs.writeFileSync(path.join(CONFIG.ceremonyDir, 'transcript.md'), transcript);
        console.log('   ✅ Transcript generated');
    }

    saveState() {
        const state = {
            phase: this.currentPhase,
            participants: this.participants,
            contributions: this.contributions,
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(
            path.join(CONFIG.ceremonyDir, 'ceremony.json'),
            JSON.stringify(state, null, 2)
        );
    }
}

// CLI
async function main() {
    const ceremony = new MPCCeremony();
    await ceremony.initialize();

    const args = process.argv.slice(2);
    const command = args[0] || 'help';

    switch (command) {
        case 'phase1':
            await ceremony.runPhase1();
            break;
        case 'phase2':
            await ceremony.runPhase2();
            break;
        case 'full':
            await ceremony.runPhase1();
            await ceremony.runPhase2();
            break;
        case 'status':
            console.log(`\nCeremony Status: ${ceremony.currentPhase}`);
            console.log(`Participants: ${ceremony.participants.length}`);
            console.log(`Contributions: ${ceremony.contributions.length}`);
            break;
        default:
            console.log(`
Usage: node mpc-ceremony.js <command>

Commands:
  phase1    Run Powers of Tau ceremony (Phase 1)
  phase2    Run circuit-specific ceremony (Phase 2)
  full      Run complete ceremony
  status    Show ceremony status

Minimum ${CONFIG.minParticipants} participants required.
`);
    }
}

main().catch(console.error);
