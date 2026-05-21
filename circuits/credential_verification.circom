pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

/*
 * CredentialVerification(numAttributes)
 *
 * Groth16 circuit for W3C Verifiable Credential selective disclosure.
 * Attributes follow the SocialMediaIdentityCredential schema:
 *   attr[0] age            -- age-gated access (predicate: >= threshold)
 *   attr[1] accountAgeDays -- account age predicate
 *   attr[2] verifiedHuman  -- Sybil resistance (selectively disclosed)
 *   attr[3] countryCode    -- geo-gating (hidden by default)
 *   attr[4] contentTier    -- creator status (hidden by default)
 *   attr[5..7]             -- reserved
 *
 * credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attr[0..n-1])
 * scopeNullifier        = Poseidon(userSecret, platformId)  -- stable per (user, platform)
 * nullifier             = Poseidon(userSecret, nullifierSeed, challenge)  -- per-session
 *
 * nPublic = 27 for n=8: outputs [0-19], public inputs [20-26].
 */

// Equality check wrapper around circomlib IsZero.
template IsEqualCustom() {
    signal input in[2];
    signal output out;

    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

// Selectively reveals an attribute: revealFlag=1 outputs raw value, 0 outputs zero.
template SelectiveDisclosure() {
    signal input attribute;
    signal input userSecret;
    signal input revealFlag;  // 1 = reveal, 0 = hide
    signal output commitment;
    signal output revealed;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== attribute;
    hasher.inputs[1] <== userSecret;

    component mux = Mux1();
    mux.c[0] <== 0;
    mux.c[1] <== attribute;
    mux.s <== revealFlag;

    commitment <== hasher.out;
    revealed <== mux.out;
}

// Proves value >= threshold using GreaterEqThan; value is not revealed.
template RangeProof(bits) {
    signal input value;
    signal input threshold;
    signal output valid;

    signal diff;
    diff <== value - threshold;

    component gte = GreaterEqThan(bits);
    gte.in[0] <== value;
    gte.in[1] <== threshold;

    valid <== gte.out;
}

// Main template. Instantiate with numAttributes=2, 4, or 8.
template CredentialVerification(numAttributes) {
    // private
    signal input userSecret;
    signal input attributes[numAttributes];
    signal input revealFlags[numAttributes];
    signal input nullifierSeed;
    signal input credentialSalt;  // high-entropy issuer nonce; hardens credentialCommitment against preimage search

    // public inputs
    signal input issuerPublicKey;
    signal input schemaHash;
    signal input challenge;
    signal input predicateThreshold;
    signal input predicateAttributeIndex;
    signal input credentialCommitment;  // Poseidon(issuerPublicKey, credentialSalt, attrs[0..n-1]); registered on-chain by issuer
    signal input platformId;

    // outputs
    signal output credentialValid;
    signal output nullifier;
    signal output attributeCommitments[numAttributes];
    signal output revealedValues[numAttributes];
    signal output predicateSatisfied;
    signal output scopeNullifier;  // Poseidon(userSecret, platformId); stable per (user, platform) for ban enforcement

    // ========== CREDENTIAL COMMITMENT VERIFICATION ==========
    // Recompute commitment as Poseidon(issuerPublicKey, credentialSalt, attrs).
    // credentialSalt is a high-entropy issuer-generated nonce included in the private
    // credential document. It prevents offline dictionary attacks: even knowing
    // issuerPublicKey and the full attribute distribution, an attacker cannot recover
    // attributes from the public credentialCommitment without the salt.
    // userSecret is excluded so the issuer can register the commitment without knowing
    // the user secret. The issuer computes the same hash offline and registers it on-chain.
    component credHasher = Poseidon(numAttributes + 2);
    credHasher.inputs[0] <== issuerPublicKey;
    credHasher.inputs[1] <== credentialSalt;
    for (var i = 0; i < numAttributes; i++) {
        credHasher.inputs[i + 2] <== attributes[i];
    }

    // Verify computed commitment matches the public (on-chain registered) commitment
    component hashCheck = IsEqualCustom();
    hashCheck.in[0] <== credHasher.out;
    hashCheck.in[1] <== credentialCommitment;
    credentialValid <== hashCheck.out;

    // ========== NULLIFIER GENERATION ==========
    // Nullifier = hash(userSecret, nullifierSeed, challenge)
    // Prevents same credential from being used twice for same challenge (per-session)
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== userSecret;
    nullifierHasher.inputs[1] <== nullifierSeed;
    nullifierHasher.inputs[2] <== challenge;
    nullifier <== nullifierHasher.out;

    // ========== SCOPE NULLIFIER (BAN PREVENTION) ==========
    // scopeNullifier = Poseidon(userSecret, platformId)
    // Stable across sessions for a given (user, platform) pair.
    // ZKVerifier.sol records this in bannedScopeNullifiers when a user is banned.
    // A banned user cannot present a new proof on the same platform even with a fresh challenge,
    // because their scopeNullifier is already rejected at the contract level.
    component scopeHasher = Poseidon(2);
    scopeHasher.inputs[0] <== userSecret;
    scopeHasher.inputs[1] <== platformId;
    scopeNullifier <== scopeHasher.out;

    // ========== SELECTIVE DISCLOSURE ==========
    component selectors[numAttributes];
    for (var i = 0; i < numAttributes; i++) {
        selectors[i] = SelectiveDisclosure();
        selectors[i].attribute <== attributes[i];
        selectors[i].userSecret <== userSecret;
        selectors[i].revealFlag <== revealFlags[i];

        attributeCommitments[i] <== selectors[i].commitment;
        revealedValues[i] <== selectors[i].revealed;
    }

    // ========== PREDICATE PROOF (RANGE CHECK) ==========
    // This schema fixes the predicate to attributes[0] (age). Enforce that the
    // public input predicateAttributeIndex must equal 0 so verifiers cannot
    // claim to be checking a different attribute index than the circuit actually uses.
    predicateAttributeIndex === 0;

    component predicateProof = RangeProof(64);
    predicateProof.value <== attributes[0];
    predicateProof.threshold <== predicateThreshold;
    predicateSatisfied <== predicateProof.valid;

    // ========== CONSTRAINTS ==========
    // Ensure reveal flags are binary (0 or 1)
    for (var i = 0; i < numAttributes; i++) {
        revealFlags[i] * (revealFlags[i] - 1) === 0;
    }
}

/**
 * Nullifier Registry Check
 * Used to prevent double-spending of credentials
 */
template NullifierCheck() {
    signal input nullifier;
    signal input registeredNullifiers[10];  // Known used nullifiers
    signal output isUnused;

    // Check nullifier is not in registry
    component checks[10];
    signal notEqual[10];
    
    for (var i = 0; i < 10; i++) {
        checks[i] = IsEqualCustom();
        checks[i].in[0] <== nullifier;
        checks[i].in[1] <== registeredNullifiers[i];
        notEqual[i] <== 1 - checks[i].out;
    }

    // All must be not-equal (product of all notEqual should be 1)
    signal products[10];
    products[0] <== notEqual[0];
    for (var i = 1; i < 10; i++) {
        products[i] <== products[i-1] * notEqual[i];
    }
    isUnused <== products[9];
}

/**
 * Age Verification Circuit
 * Standalone circuit for age-only verification
 * Proves: userAge >= minimumAge without revealing exact age
 */
template AgeVerification() {
    // Private inputs
    signal input userAge;
    signal input userSecret;
    signal input credentialHash;

    // Public inputs
    signal input minimumAge;
    signal input issuerPublicKey;
    signal input challenge;

    // Outputs
    signal output ageRequirementMet;
    signal output proofHash;

    // Range proof for age
    component ageCheck = RangeProof(8);  // 8 bits = max age 255
    ageCheck.value <== userAge;
    ageCheck.threshold <== minimumAge;
    ageRequirementMet <== ageCheck.valid;

    // Create proof hash for verification
    component proofHasher = Poseidon(4);
    proofHasher.inputs[0] <== userSecret;
    proofHasher.inputs[1] <== issuerPublicKey;
    proofHasher.inputs[2] <== minimumAge;
    proofHasher.inputs[3] <== challenge;
    proofHash <== proofHasher.out;
}

// ========== MAIN COMPONENT ==========
// Instantiate with 8 attributes (name, age, country, email, etc.)
component main {public [issuerPublicKey, schemaHash, challenge, predicateThreshold, predicateAttributeIndex, credentialCommitment, platformId]} = CredentialVerification(8);
