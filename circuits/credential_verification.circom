pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

/**
 * @journal JOURNAL 3 — Privacy-Preserving ZK Credential Verification (in progress)
 *
 * Application domain: Social Media Identity Management
 *   Extends Journal 2 (DID-anchored VC + on-chain revocation) with a ZK
 *   privacy layer. The 8 circuit attributes map to the SocialMediaIdentityCredential
 *   schema used across this codebase:
 *     attr[0] age            — COPPA/GDPR age-gated access (predicate: >= 18)
 *     attr[1] accountAgeDays — anti-spam: proves account >= 30 days (predicate)
 *     attr[2] verifiedHuman  — Sybil resistance (selectively disclosed)
 *     attr[3] countryCode    — geo-gating (ISO 3166-1 numeric, hidden by default)
 *     attr[4] contentTier    — creator/verified status (hidden by default)
 *     attr[5..7]             — reserved for future social media attributes
 *
 * Role: Main ZK circuit. Proves W3C VC credential validity and selective
 *       attribute disclosure using Groth16 over BN128, Poseidon hashing,
 *       and a challenge-bound nullifier (replay protection).
 *
 * STATUS: HARDENED — Option A + Issue 2 (ban evasion) + CB2 (credentialSalt) fixes applied.
 *   credentialHash (private) replaced by credentialCommitment (PUBLIC).
 *   credentialSalt (PRIVATE) added to prevent offline dictionary attacks on commitment.
 *   credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attr[0..7]).
 *   scopeNullifier = Poseidon(userSecret, platformId) added as second public output.
 *   platformId added as public input.
 *   nPublic = 27 (unchanged — credentialSalt is private), constraints updated after recompile.
 *   Outputs [0-19]: credentialValid, nullifier, attrCommitments[8],
 *                   revealedValues[8], predicateSatisfied, scopeNullifier
 *   Public inputs [20-26]: issuerPublicKey, schemaHash, challenge,
 *                          predicateThreshold, predicateAttributeIndex,
 *                          credentialCommitment, platformId
 *
 * Known limitations (to be disclosed in paper §Limitations):
 *   - predicateProof always checks attributes[0] regardless of predicateAttributeIndex;
 *     for the social media use case this is acceptable (age is always attr[0]),
 *     but a general-purpose circuit would use a MUX tree for arbitrary index.
 *   - NullifierCheck (on-circuit) is illustrative with 10 slots; production
 *     double-spend prevention is enforced by ZKVerifier.sol's usedNullifiers mapping.
 *   - scopeNullifier is stable per (user, platform) pair — the platform can link
 *     all proofs from the same user on that platform via scopeNullifier. This is
 *     an intentional trade-off for ban prevention, consistent with Semaphore's design.
 *
 * NOT used in Journal 2. Journal 2 uses Ed25519 off-chain signatures only.
 *
 * CredentialVerification Circuit
 *
 * Implements privacy-preserving credential verification with:
 * - Selective attribute disclosure
 * - Credential validity proof without revealing content
 * - Predicate proofs (e.g., age >= 18 without revealing exact age)
 *
 * PhD Research: Blockchain-based Privacy-Preserving IAM System
 */

/**
 * IsEqual component - checks if two values are equal
 * Returns 1 if equal, 0 otherwise
 */
template IsEqualCustom() {
    signal input in[2];
    signal output out;

    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

/**
 * SelectiveDisclosure - reveals attribute only if flag is set
 * If flag = 1: output = raw attribute value (plaintext)
 * If flag = 0: output = 0 (hidden)
 */
template SelectiveDisclosure() {
    signal input attribute;
    signal input userSecret;
    signal input revealFlag;  // 1 = reveal, 0 = hide
    signal output commitment;
    signal output revealed;

    // Create commitment using Poseidon hash
    component hasher = Poseidon(2);
    hasher.inputs[0] <== attribute;
    hasher.inputs[1] <== userSecret;

    // Use multiplexer to conditionally reveal the raw attribute value
    // c[0]=0 (hidden), c[1]=attribute (revealed plaintext when revealFlag=1)
    component mux = Mux1();
    mux.c[0] <== 0;
    mux.c[1] <== attribute;
    mux.s <== revealFlag;

    commitment <== hasher.out;
    revealed <== mux.out;
}

/**
 * RangeProof - proves value >= threshold without revealing value
 * Used for age verification, income thresholds, etc.
 */
template RangeProof(bits) {
    signal input value;
    signal input threshold;
    signal output valid;

    // value - threshold should be >= 0 for value >= threshold
    signal diff;
    diff <== value - threshold;

    // Check if diff >= 0 using GreaterEqThan
    component gte = GreaterEqThan(bits);
    gte.in[0] <== value;
    gte.in[1] <== threshold;

    valid <== gte.out;
}

/**
 * Main CredentialVerification Template
 * 
 * Verifies credential authenticity and enables selective disclosure
 * Maximum 8 attributes supported (extendable)
 */
template CredentialVerification(numAttributes) {
    // ========== PRIVATE INPUTS (hidden from verifier) ==========
    signal input userSecret;               // User's private secret
    signal input attributes[numAttributes]; // Credential attributes
    signal input revealFlags[numAttributes]; // Which attributes to reveal (0 or 1)
    signal input nullifierSeed;            // Prevents double-use of same proof
    signal input credentialSalt;          // Issuer-generated high-entropy nonce; prevents
                                           // offline dictionary attacks on credentialCommitment

    // ========== PUBLIC INPUTS (visible to verifier) ==========
    signal input issuerPublicKey;          // Issuer's public identifier
    signal input schemaHash;               // Schema identifier
    signal input challenge;                // Verifier's random challenge
    signal input predicateThreshold;       // For range proofs (e.g., age >= 18)
    signal input predicateAttributeIndex;  // Which attribute to check predicate on
    // credentialCommitment = Poseidon(issuerPublicKey, credentialSalt, attrs[0..7]) registered on-chain by issuer.
    // Making this PUBLIC binds the prover to issuer-authorised attributes (Option A fix).
    signal input credentialCommitment;     // On-chain issuer commitment to (issuerPublicKey, attrs)
    signal input platformId;              // Platform's stable identifier (for ban prevention)

    // ========== OUTPUTS ==========
    signal output credentialValid;         // 1 if credential is valid
    signal output nullifier;               // Unique proof identifier (per-session, challenge-bound)
    signal output attributeCommitments[numAttributes]; // Commitments to all attributes
    signal output revealedValues[numAttributes];       // Revealed attribute values (0 if hidden)
    signal output predicateSatisfied;      // 1 if predicate is satisfied
    signal output scopeNullifier;          // Stable per-(user, platform) identifier for ban enforcement

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
