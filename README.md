# Privacy-Preserving Zero-Knowledge Credential Verification for Social Media Identity Management

This repository contains the implementation artifacts for the paper:

> **On-Chain Zero-Knowledge Credential Verification for Internet Identity: Gas, Latency, and Scalability**
> Vineeta Rathore, Manoj Kumar Rawat
> *Under review — ACM Transactions on Internet Technology (TOIT)*

Release tag **v1.0.0** corresponds to the exact artifact set used for all reported benchmarks.

---

## Repository Structure

```
circuits/
  credential_verification.circom     CredentialVerification(8) — 6,768 R1CS constraints
  credential_verification_2.circom   CredentialVerification(2) — scaling experiment
  credential_verification_4.circom   CredentialVerification(4) — scaling experiment

contracts/
  Groth16Verifier.sol   Auto-generated BN128 Groth16 verifier (verifyProof)
  ZKVerifier.sol        On-chain policy enforcement (nullifiers, ban-evasion, Sybil gating)
  DIDRegistry.sol       W3C DID registry (identity anchoring; gas not measured in paper)

scripts/
  generate-test-input.js    Generate circuit inputs and run proof-generation benchmark
  latency-raw-n8.js         50-run benchmark producing latency_raw_n8.json (49 warm samples)
  fig3_latency_boxplot.py   Figure 3 generation script (loads real samples, no synthetic data)
  scaling-experiment.js     Full n=2/4/8 scaling experiment
  measure-metrics.js        Combined latency + gas benchmarking
  setup-circuit.js          Trusted setup: compile circuit, generate zkey
  mpc-ceremony.js           Multi-party contribution stub (Phase 2)
  deploy.js                 Local Hardhat deployment
  deploy-testnet.js         Sepolia testnet deployment

test/
  ZKVerifier.gas.test.js        Gas measurement for verifyProof() and verifyCredentialProof()
  ZKVerifier.fullgas.test.js    End-to-end gas measurement
  DIDRegistry.test.js           Unit tests for DID registry
  VerifiableCredential.test.js  VC issuance and verification tests

build/circuits/
  verification_key.json         Groth16 verification key (BN128, nPublic=27)
  proof.json                    Sample proof output (256 bytes, constant Groth16)
  public.json                   Sample public signals (27 values)
  test_input.json               Sample circuit input
  latency_raw_n8.json           49 actual warm-run latency measurements (source for Figure 3)
  benchmark_report.json         Full benchmark summary
  scaling/scaling_results.json  n=2/4/8 scaling experiment results
  SETUP_INFO.md                 Trusted setup provenance and ceremony details
  credential_verification_js/   Compiled WASM witness calculator
```

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Circuit constraints (R1CS) | 6,768 |
| Circuit wires | 6,785 |
| Private inputs | 19 |
| Public inputs | 7 |
| Circuit outputs | 20 |
| nPublic (pubSignals) | 27 |
| Proof size | 256 bytes (constant, Groth16) |
| Mean proof latency (warm, n=49) | 414.6 ms (σ = 56.1 ms, ddof=1) |
| Median latency (p50) | 415.5 ms |
| p95 latency | 499.3 ms |
| Min / Max latency (warm) | 333.6 ms / 555.8 ms |
| Cold-start latency (excluded) | 649.1 ms |
| `Groth16Verifier.verifyProof()` gas | 396,197 |
| `ZKVerifier.verifyCredentialProof()` gas | 555,734 |
| Hardware | Intel Core i5-1235U, 16 GB RAM, Windows 11 |

### Attribute Scaling

| n | Constraints | Mean latency | σ | p95 | `verifyProof` gas |
|---|-------------|-------------|---|-----|-------------------|
| 2 | 2,970 | 240.9 ms | 41.1 ms | 305.2 ms | 312,581 |
| 4 | 4,239 | 313.8 ms | 48.2 ms | 407.0 ms | 340,465 |
| 8 | 6,768 | 414.6 ms | 56.1 ms | 499.3 ms | 396,197 |

~633 additional R1CS constraints per attribute; ~6,968 gas per additional public signal.

---

## pubSignals[27] Layout

| Index | Signal | Type |
|-------|--------|------|
| 0 | credentialValid | output |
| 1 | nullifier | output |
| 2–9 | attributeCommitments[8] | output |
| 10–17 | revealedValues[8] | output |
| 18 | predicateSatisfied | output |
| 19 | scopeNullifier | output |
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
2. **Sybil resistance** — selectively discloses `verifiedHuman` attribute via Mux1 gating (raw value when `revealFlag=1`, zero otherwise)
3. **Ban-evasion prevention** — stable `scopeNullifier = Poseidon(userSecret, platformId)` per (user, platform) pair; session `nullifier = Poseidon(userSecret, nullifierSeed, challenge)` prevents proof replay

---

## Software Stack

- [Circom 2.2.3](https://github.com/iden3/circom)
- [snarkjs 0.7.6](https://github.com/iden3/snarkjs)
- Node.js v22.10.0
- [Hardhat 2.27.2](https://hardhat.org/)
- ethers.js 5.7.2
- Solidity ^0.8.20

**Hardware**: 12th Gen Intel Core i5-1235U, 10 cores, 16 GB RAM, Windows 11

---

## Reproducing the Benchmarks

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the 50-run latency benchmark (produces `build/circuits/latency_raw_n8.json`):
   ```bash
   node scripts/latency-raw-n8.js
   ```

3. Generate Figure 3 from the raw samples (requires Python 3 + matplotlib + numpy):
   ```bash
   python scripts/fig3_latency_boxplot.py
   ```

4. Run gas measurement tests:
   ```bash
   npx hardhat test test/ZKVerifier.gas.test.js
   npx hardhat test test/ZKVerifier.fullgas.test.js
   ```

5. Run the full n=2/4/8 scaling experiment:
   ```bash
   node scripts/scaling-experiment.js
   ```

> **Note:** The trusted setup (`.ptau` and `.zkey` files) is not included due to file size.
> Run `node scripts/setup-circuit.js` to regenerate locally, or download
> `powersOfTau28_hez_final_14.ptau` from the
> [Hermez trusted setup repository](https://github.com/iden3/snarkjs#7-prepare-phase-2).

### Dependency Security Note

`npm audit` reports known vulnerabilities in transitive dependencies of Hardhat/Waffle/Ganache.
These affect the local development toolchain only. The circuit, proving key, and on-chain
verifier contract (`Groth16Verifier.sol`) are not affected. This artifact is a research
prototype and is **not intended for production deployment**.

---

## Trusted Setup

The universal SRS uses `powersOfTau28_hez_final_14.ptau` from the Perpetual Powers-of-Tau
ceremony coordinated by iden3. The circuit-specific Phase 2 key was generated by a single
party — acknowledged as a limitation in the paper (Section 8). A multi-party ceremony is
listed as future work.

See `build/circuits/SETUP_INFO.md` for full provenance.

---

## Security Note

The `.env` file containing RPC endpoints and deployer private keys is **not included**.
Create your own `.env` for testnet deployment:

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
  title   = {On-Chain Zero-Knowledge Credential Verification for Internet
             Identity: {Gas}, Latency, and Scalability},
  journal = {ACM Transactions on Internet Technology},
  year    = {2026},
  note    = {Under review}
}
```
