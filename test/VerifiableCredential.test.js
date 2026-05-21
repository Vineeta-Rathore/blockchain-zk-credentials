// End-to-end tests for the W3C VC Ed25519 pipeline: issuance, verification, and revocation.

const { expect } = require('chai');
const { ethers } = require('hardhat');
const {
  VerifiableCredentialService,
  rawEd25519PublicKeyFromMultibase,
  rawEd25519SecretKeyFromMultibase,
} = require('../src/vc/vc-service');
const { CredentialVerifierService } = require('../src/vc/verifier-service');

describe('W3C VC credential pipeline', function () {
  let didRegistry;
  let issuer;
  let holder;
  let attacker;
  let issuerDid;
  let holderDid;
  let issuerKeys;
  let holderKeys;
  let issuerVerificationMethod;
  let verifierService;

  beforeEach(async function () {
    [, issuer, holder, attacker] = await ethers.getSigners();

    const DIDRegistry = await ethers.getContractFactory('DIDRegistry');
    didRegistry = await DIDRegistry.deploy();
    await didRegistry.deployed();

    verifierService = new CredentialVerifierService(didRegistry);
    issuerDid = 'did:journal2:issuer';
    holderDid = 'did:journal2:holder';
    issuerKeys = VerifiableCredentialService.generateEd25519KeyPair();
    holderKeys = VerifiableCredentialService.generateEd25519KeyPair();

    issuerVerificationMethod = VerifiableCredentialService.createVerificationMethod(
      issuerDid,
      issuerKeys.publicKeyMultibase
    );

    const holderVerificationMethod = VerifiableCredentialService.createVerificationMethod(
      holderDid,
      holderKeys.publicKeyMultibase
    );

    await didRegistry.connect(issuer).createDID(
      issuerDid,
      [JSON.stringify(issuerVerificationMethod)],
      ['CredentialIssuerService'],
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes('issuer metadata'))
    );

    await didRegistry.connect(holder).createDID(
      holderDid,
      [JSON.stringify(holderVerificationMethod)],
      ['CredentialHolderService'],
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes('holder metadata'))
    );
  });

  function issueCredential(overrides = {}) {
    return VerifiableCredentialService.issueCredential({
      issuerDid,
      subjectDid: holderDid,
      privateKeyMultibase: issuerKeys.privateKeyMultibase,
      verificationMethod: issuerVerificationMethod,
      registryAddress: didRegistry.address,
      claims: {
        name: 'Verified Identity',
        accessLevel: 'research-lab',
      },
      credentialType: 'IdentityCredential',
      ...overrides,
    });
  }

  it('verifies a valid Ed25519-signed VC successfully', async function () {
    const credential = issueCredential();

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(true);
    expect(result.reason).to.equal('VALID');
    expect(result.issuerDid).to.equal(issuerDid);
    expect(result.subjectDid).to.equal(holderDid);
  });

  it('uses a W3C Ed25519 multikey value with 0xed01 prefix and 32-byte raw key', async function () {
    const rawKey = rawEd25519PublicKeyFromMultibase(issuerKeys.publicKeyMultibase);

    expect(issuerKeys.publicKeyMultibase.startsWith('z')).to.equal(true);
    expect(rawKey.length).to.equal(32);
  });

  it('uses a W3C Ed25519 secret multikey value with 0x8026 prefix and 32-byte raw key', async function () {
    const rawSecretKey = rawEd25519SecretKeyFromMultibase(issuerKeys.secretKeyMultibase);

    expect(issuerKeys.secretKeyMultibase.startsWith('z')).to.equal(true);
    expect(rawSecretKey.length).to.equal(32);
    expect(issuerKeys.privateKeyMultibase).to.equal(issuerKeys.secretKeyMultibase);
  });

  it('fails when the credential subject is tampered', async function () {
    const credential = issueCredential();
    credential.credentialSubject.accessLevel = 'admin';

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('INVALID_SIGNATURE');
  });

  it('fails when the issuer DID is tampered', async function () {
    const credential = issueCredential();
    credential.issuer = 'did:journal2:unknown-issuer';

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('ISSUER_DID_INACTIVE_OR_UNKNOWN');
  });

  it('fails when the credential is signed with the wrong issuer key', async function () {
    const attackerKeys = VerifiableCredentialService.generateEd25519KeyPair();
    const credential = issueCredential({
      privateKeyMultibase: attackerKeys.privateKeyMultibase,
    });

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('INVALID_SIGNATURE');
  });

  it('fails when the credential has expired', async function () {
    const credential = issueCredential({
      validFrom: '2024-01-01T00:00:00.000Z',
      validUntil: '2024-01-02T00:00:00.000Z',
    });

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('CREDENTIAL_EXPIRED');
  });

  it('fails when the credential is revoked on-chain', async function () {
    const credential = issueCredential();

    const tx = await didRegistry.connect(issuer).revokeCredential(
      issuerDid,
      credential.id,
      'Credential withdrawn by issuer'
    );
    const receipt = await tx.wait();
    console.log(`Gas used for credential revocation: ${receipt.gasUsed.toString()}`);

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('CREDENTIAL_REVOKED');
  });

  it('fails when the issuer DID is inactive', async function () {
    const credential = issueCredential();
    await didRegistry.connect(issuer).deactivateDID(issuerDid);

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('ISSUER_DID_INACTIVE_OR_UNKNOWN');
  });

  it('fails when the subject DID is inactive', async function () {
    const credential = issueCredential();
    await didRegistry.connect(holder).deactivateDID(holderDid);

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('SUBJECT_DID_INACTIVE_OR_UNKNOWN');
  });

  it('documents duplicate credential ID behavior through the revocation registry', async function () {
    const credentialId = 'urn:uuid:duplicate-journal2-id';
    const firstCredential = issueCredential({ credentialId });
    const secondCredential = issueCredential({ credentialId });

    expect(firstCredential.id).to.equal(secondCredential.id);

    await didRegistry.connect(issuer).revokeCredential(issuerDid, credentialId, 'Duplicate ID retired');

    const firstResult = await verifierService.verifyCredential(firstCredential);
    const secondResult = await verifierService.verifyCredential(secondCredential);

    expect(firstResult.reason).to.equal('CREDENTIAL_REVOKED');
    expect(secondResult.reason).to.equal('CREDENTIAL_REVOKED');
  });

  it('rejects duplicate revocation attempts', async function () {
    const credential = issueCredential();
    await didRegistry.connect(issuer).revokeCredential(issuerDid, credential.id, 'Initial revocation');

    await expect(
      didRegistry.connect(issuer).revokeCredential(issuerDid, credential.id, 'Second revocation')
    ).to.be.revertedWith('DIDRegistry: Already revoked');
  });

  it('prevents non-controller credential revocation', async function () {
    const credential = issueCredential();

    await expect(
      didRegistry.connect(attacker).revokeCredential(issuerDid, credential.id, 'Unauthorized')
    ).to.be.revertedWith('DIDRegistry: Not authorized');
  });

  it('fails on a malformed credential missing required fields', async function () {
    const result = await verifierService.verifyCredential({});

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('MALFORMED_CREDENTIAL');
  });

  it('fails when the issuer verification method has been rotated off the DID document', async function () {
    const credential = issueCredential();

    // Replace issuer DID's verification methods with a new key under a different key ID.
    // The credential's proof.verificationMethod still references did:journal2:issuer#key-1,
    // which is now absent from the DID document, triggering Step V5.
    const newKeys = VerifiableCredentialService.generateEd25519KeyPair();
    const newVerificationMethod = VerifiableCredentialService.createVerificationMethod(
      issuerDid,
      newKeys.publicKeyMultibase,
      'key-2'
    );
    const newDataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('key-rotated'));
    await didRegistry.connect(issuer).updateDID(
      issuerDid,
      [JSON.stringify(newVerificationMethod)],
      ['CredentialIssuerService'],
      newDataHash
    );

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('VERIFICATION_METHOD_NOT_FOUND');
  });

  it('fails when the proof configuration is tampered after signing', async function () {
    const credential = issueCredential();

    // Mutate proof.created — changes the proofConfig hash in the dual-hash pipeline
    // (SHA-256(proofConfig) || SHA-256(document)) without altering the document,
    // so Step V5 passes but Step V6 Ed25519 verification fails.
    credential.proof.created = '2000-01-01T00:00:00.000Z';

    const result = await verifierService.verifyCredential(credential);

    expect(result.valid).to.equal(false);
    expect(result.reason).to.equal('INVALID_SIGNATURE');
  });

  it('measures end-to-end credential verification latency for evaluation reporting', async function () {
    const credential = issueCredential();
    const samples = [];

    for (let i = 0; i < 100; i++) {
      const start = process.hrtime.bigint();
      const result = await verifierService.verifyCredential(credential);
      const end = process.hrtime.bigint();

      expect(result.valid).to.equal(true);
      samples.push(Number(end - start) / 1_000_000);
    }

    samples.sort((a, b) => a - b);
    const p50 = samples[Math.floor(samples.length * 0.5)];
    const p95 = samples[Math.floor(samples.length * 0.95)];
    const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;

    console.log(`VC verification latency over 100 runs: mean=${mean.toFixed(3)}ms p50=${p50.toFixed(3)}ms p95=${p95.toFixed(3)}ms`);
    expect(p95).to.be.lessThan(250);
  });
});
