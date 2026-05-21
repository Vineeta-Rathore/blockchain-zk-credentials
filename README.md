# Privacy-Preserving Zero-Knowledge Credential Verification for Social Media Identity Management

This repository contains the implementation artifacts for the paper:

> **Privacy-Preserving Zero-Knowledge Credential Verification for Social Media Identity Management**
> Vineeta Rathore, Manoj Kumar Rawat
> *Under review — Journal of Information Security and Applications (JISA), Elsevier*

---

## Repository Structure

```
circuits/
  credential_verification.circom   CredentialVerification(8) — 6,767 R1CS constraints
  age_verification.circom          Age-predicate sub-circuit
  age_verification_js/             Compiled witness calculator for age circuit

contracts/
  Groth16Verifier.sol      Auto-generated BN128 Groth16 verifier (verifyProof)
  AgeGroth16Verifier.sol   Age-only verifier for gas comparison
  ZKVerifier.sol           On-chain policy enforcement (nullifiers, ban-evasion, Sybil gating)
  DIDRegistry.sol          W3C DID registry from companion system (Journal 2)

scripts/
  generate-test-input.js   Generate circuit inputs from credential data (benchmark entrypoint)
  measure-metrics.js       Latency + gas benchmarking script (n=49 warm runs)
  setup-circuit.js         Trusted setup: compile circuit, generate zkey
  mpc-ceremony.js          Multi-party contribution stub (Phase 2)
  deploy.js                Local Hardhat deployment
  deploy-testnet.js        Sepolia testnet deployment

test/
  ZKVerifier.gas.test.js   Gas measurement tests for ZKVerifier.sol
  AgeVerifier.gas.test.js  Gas measurement tests for AgeGroth16Verifier.sol
  DIDRegistry.test.js      Unit tests for DID registry
  VerifiableCredential.test.js  VC issuance and verification tests

build/circuits/
  verification_key.json    Groth16 verification key (BN128, nPublic=27)
  proof.json               Sample proof output (256 bytes)
  public.json              Sample public signals (27 values)
  test_input.json          Sample circuit input
  benchmark_report.json    Full benchmark results (n=49 latency measurements)
  SETUP_INFO.md            Trusted setup provenance and ceremony details
  credential_verification_js/  Compiled WASM witness calculator
```

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Circuit constraints (R1CS) | 6,767 |
| Circuit wires | 6,785 |
| Private inputs | 19 |
| Public inputs | 7 |
| Circuit outputs | 20 |
| nPublic (pubSignals) | 27 |
| Proof size | 256 bytes (constant, Groth16) |
| Mean proof latency (warm, n=49) | 430.6 ms (σ = 43.6 ms) |
| Median latency (p50) | 441.9 ms |
| p95 latency | 490.3 ms |
| Min / Max latency (warm) | 325.7 ms / 506.5 ms |
| Cold-start latency (excluded) | 689.2 ms |
| Groth16Verifier.verifyProof() gas | 396,569 (deterministic) |
| ZKVerifier.verifyCredentialProof() gas | 556,119 |
| Blockchain | Ethereum Sepolia (BN128 / EIP-197) |

---

## pubSignals[27] Layout

| Index | Signal | Type |
|-------|--------|------|
| 0 | credentialValid | output |
| 1 | nullifier η | output |
| 2–9 | attributeCommitments[8] | output |
| 10–17 | revealedValues[8] | output |
| 18 | predicateSatisfied | output |
| 19 | scopeNullifier ηₛ | output |
| 20 | issuerPublicKey | public input |
| 21 | schemaHash | public input |
| 22 | challenge | public input |
| 23 | predicateThreshold | public input |
| 24 | predicateAttributeIndex | public input |
| 25 | credentialCommitment | public input |
| 26 | platformId | public input |

---

## ZK Use Cases

1. **Age-gated access** — proves `age >= predicateThreshold` (COPPA/GDPR) without revealing the exact age value
2. **Sybil resistance** — selectively discloses `verifiedHuman` attribute via Mux1 gating
3. **Ban-evasion prevention** — stable `scopeNullifier = Poseidon(userSecret, platformId)` per (user, platform) pair; session `nullifier = Poseidon(userSecret, nullifierSeed, challenge)` prevents proof replay

---

## Software Stack

- [Circom 2.2.3](https://github.com/iden3/circom)
- [snarkjs 0.7.6](https://github.com/iden3/snarkjs)
- Node.js v22.10.0
- [Hardhat 2.17.0](https://hardhat.org/)
- ethers.js 5.7.2
- Solidity ^0.8.19

**Hardware**: 12th Gen Intel Core i5-1235U, 10 cores, 16 GB RAM, Windows 11

---

## Reproducing the Benchmarks

1. Install dependencies:
   ```bash
   npm install
   ```

2. Generate circuit inputs and run proof generation benchmark:
   ```bash
   node scripts/generate-test-input.js
   node scripts/measure-metrics.js
   ```

3. Run gas tests (requires local Hardhat node):
   ```bash
   npx hardhat test test/ZKVerifier.gas.test.js
   npx hardhat test test/AgeVerifier.gas.test.js
   ```

> **Note:** The trusted setup (`.ptau` and `.zkey` files) is not included due to file size.
> Run `node scripts/setup-circuit.js` to regenerate locally, or download
> `powersOfTau28_hez_final_14.ptau` from the
> [Hermez trusted setup repository](https://github.com/iden3/snarkjs#7-prepare-phase-2).

---

## Trusted Setup

The universal SRS uses `powersOfTau28_hez_final_14.ptau` from the Perpetual Powers-of-Tau
ceremony coordinated by iden3, from which the Hermez network selected the first 54
independent contributions plus a random beacon. The circuit-specific Phase 2 key was
generated by a single party — acknowledged as a limitation in the paper (Section 7).
A multi-party ceremony is listed as future work.

See `build/circuits/SETUP_INFO.md` for full provenance.

---

## Security Note

The `.env` file containing RPC endpoints and deployer private keys is **not included**.
Create your own `.env`:

```
SEPOLIA_RPC_URL=<your Infura/Alchemy Sepolia endpoint>
PRIVATE_KEY=<deployer wallet private key>
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Citation

```bibtex
@article{rathore2026zkvc,
  author  = {Rathore, Vineeta and Rawat, Manoj Kumar},
  title   = {Privacy-Preserving Zero-Knowledge Credential Verification
             for Social Media Identity Management},
  journal = {Journal of Information Security and Applications},
  year    = {2026},
  note    = {Under review}
}
```