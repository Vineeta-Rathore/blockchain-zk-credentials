// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Groth16Verifier.sol";

/**
 * @title ZKVerifier
 * @notice Wraps the snarkjs-generated Groth16Verifier with nullifier tracking,
 *         trusted-issuer gating, credential registration, and ban enforcement.
 *
 * pubSignals layout (nPublic=27, circom output-then-input ordering):
 *   [0]     credentialValid
 *   [1]     nullifier          -- Poseidon(userSecret, nullifierSeed, challenge)
 *   [2-9]   attributeCommitments[8]
 *   [10-17] revealedValues[8]
 *   [18]    predicateSatisfied
 *   [19]    scopeNullifier     -- Poseidon(userSecret, platformId)
 *   [20]    issuerPublicKey
 *   [21]    schemaHash
 *   [22]    challenge
 *   [23]    predicateThreshold
 *   [24]    predicateAttributeIndex
 *   [25]    credentialCommitment
 *   [26]    platformId
 */
contract ZKVerifier {
    Groth16Verifier public immutable groth16;
    
    // ========== STRUCTS ==========
    
    /**
     * @notice Groth16 proof structure
     */
    struct Proof {
        uint256[2] a;      // G1 point
        uint256[2][2] b;   // G2 point
        uint256[2] c;      // G1 point
    }

    /**
     * @notice Public inputs for credential verification
     */
    struct PublicInputs {
        uint256 issuerPublicKey;
        uint256 schemaHash;
        uint256 challenge;
        uint256 predicateThreshold;
        uint256 predicateAttributeIndex;
        uint256 credentialCommitment;   // Poseidon(issuerPublicKey, credentialSalt, attrs[0..7]) -- must be registered by issuer
        uint256 platformId;             // Platform's stable identifier; bound into scopeNullifier
        uint256 credentialValid;
        uint256 nullifier;
        uint256 predicateSatisfied;
        uint256 scopeNullifier;         // Poseidon(userSecret, platformId) — stable per (user, platform)
        uint256[8] attributeCommitments;
        uint256[8] revealedValues;
    }

    /**
     * @notice Verification result with details
     */
    struct VerificationResult {
        bool valid;
        uint256 nullifier;
        bool predicateSatisfied;
        uint256 timestamp;
        address verifier;
    }

    // ========== STATE VARIABLES ==========
    
    // Nullifier registry to prevent proof reuse (per-session, challenge-bound)
    mapping(uint256 => bool) public usedNullifiers;

    // Banned scope nullifiers — Poseidon(userSecret, platformId), stable per (user, platform)
    // Set by admin when a user is banned; blocks all future proofs from that user on that platform
    mapping(uint256 => bool) public bannedScopeNullifiers;

    // Trusted issuers
    mapping(uint256 => bool) public trustedIssuers;

    // Issuer-registered credential commitments: issuerKey => credentialCommitment => registered
    // Issuer calls registerCredential() at issuance time; prover must know attrs matching this commitment.
    mapping(uint256 => mapping(uint256 => bool)) public issuerCredentialRegistry;
    
    // Verification history for auditing
    mapping(bytes32 => VerificationResult) public verificationHistory;
    
    // Admin
    address public admin;
    
    // Paused state for emergency
    bool public paused;

    // ========== EVENTS ==========
    
    event ProofVerified(
        bytes32 indexed verificationId,
        address indexed verifier,
        uint256 nullifier,
        bool predicateSatisfied,
        uint256 timestamp
    );

    event NullifierUsed(uint256 indexed nullifier, address indexed user);
    event UserBanned(uint256 indexed scopeNullifier);
    event UserUnbanned(uint256 indexed scopeNullifier);
    event CredentialRegistered(uint256 indexed issuerKey, uint256 indexed credentialCommitment);
    event IssuerAdded(uint256 indexed issuerKey);
    event IssuerRemoved(uint256 indexed issuerKey);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // ========== MODIFIERS ==========
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "ZKVerifier: Admin only");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "ZKVerifier: Contract paused");
        _;
    }

    // ========== CONSTRUCTOR ==========
    
    constructor(address _groth16Verifier) {
        admin = msg.sender;
        groth16 = Groth16Verifier(_groth16Verifier);
    }

    // ========== MAIN VERIFICATION FUNCTIONS ==========

    /**
     * @notice Verify a ZK proof for credential verification
     * @param proof The Groth16 proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     * @return verificationId Unique ID for this verification
     */
    function verifyCredentialProof(
        Proof calldata proof,
        PublicInputs calldata inputs
    ) external whenNotPaused returns (bool valid, bytes32 verificationId) {
        // Check nullifier hasn't been used (per-session replay prevention)
        require(!usedNullifiers[inputs.nullifier], "ZKVerifier: Nullifier already used");

        // Check scope nullifier is not banned (ban-evasion prevention)
        // scopeNullifier = Poseidon(userSecret, platformId) is stable across sessions;
        // a banned user cannot generate a new proof on the same platform even with a fresh challenge.
        require(!bannedScopeNullifiers[inputs.scopeNullifier], "ZKVerifier: User banned");

        // Check issuer is trusted
        require(trustedIssuers[inputs.issuerPublicKey], "ZKVerifier: Untrusted issuer");

        // Check the credential commitment was registered by this issuer at issuance time.
        // This binds the prover to issuer-authorised attributes; a fabricated credential
        // cannot pass unless the issuer explicitly called registerCredential() for it.
        require(
            issuerCredentialRegistry[inputs.issuerPublicKey][inputs.credentialCommitment],
            "ZKVerifier: Unregistered credential"
        );

        // Verify the proof
        valid = _verifyProof(proof, inputs);
        require(valid, "ZKVerifier: Invalid proof");

        // Ensure the circuit confirmed credential binding (not just proof validity)
        require(inputs.credentialValid == 1, "ZKVerifier: Invalid credential");

        // Enforce age-gated access on-chain: the platform contract cannot proceed
        // unless the ZK circuit proved attr[0] >= predicateThreshold (COPPA/GDPR).
        require(inputs.predicateSatisfied == 1, "ZKVerifier: Predicate not satisfied");

        if (valid) {
            // Mark nullifier as used
            usedNullifiers[inputs.nullifier] = true;
            emit NullifierUsed(inputs.nullifier, msg.sender);
            
            // Create verification ID
            verificationId = keccak256(abi.encodePacked(
                msg.sender,
                inputs.nullifier,
                block.timestamp
            ));
            
            // Store verification result
            verificationHistory[verificationId] = VerificationResult({
                valid: true,
                nullifier: inputs.nullifier,
                predicateSatisfied: inputs.predicateSatisfied == 1,
                timestamp: block.timestamp,
                verifier: msg.sender
            });
            
            emit ProofVerified(
                verificationId,
                msg.sender,
                inputs.nullifier,
                inputs.predicateSatisfied == 1,
                block.timestamp
            );
        }
        
        return (valid, verificationId);
    }

    /**
     * @notice Verify a proof without consuming the nullifier (view only)
     * @param proof The Groth16 proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifyProofView(
        Proof calldata proof,
        PublicInputs calldata inputs
    ) external view returns (bool valid) {
        return _verifyProof(proof, inputs);
    }

    // ========== INTERNAL VERIFICATION ==========

    // Builds the public signals array expected by Groth16Verifier.verifyProof().
    // Signal ordering matches circom output-then-input convention (27 signals total).
    // Outputs [0-19]: credentialValid, nullifier, attributeCommitments[8],
    //                 revealedValues[8], predicateSatisfied, scopeNullifier
    // Public inputs [20-26]: issuerPublicKey, schemaHash, challenge, predicateThreshold,
    //                        predicateAttributeIndex, credentialCommitment, platformId
    function _verifyProof(
        Proof calldata proof,
        PublicInputs memory inputs
    ) internal view returns (bool) {
        uint[27] memory pubSignals;
        pubSignals[0]  = inputs.credentialValid;
        pubSignals[1]  = inputs.nullifier;
        for (uint i = 0; i < 8; i++) {
            pubSignals[2 + i] = inputs.attributeCommitments[i];
        }
        for (uint i = 0; i < 8; i++) {
            pubSignals[10 + i] = inputs.revealedValues[i];
        }
        pubSignals[18] = inputs.predicateSatisfied;
        pubSignals[19] = inputs.scopeNullifier;
        pubSignals[20] = inputs.issuerPublicKey;
        pubSignals[21] = inputs.schemaHash;
        pubSignals[22] = inputs.challenge;
        pubSignals[23] = inputs.predicateThreshold;
        pubSignals[24] = inputs.predicateAttributeIndex;
        pubSignals[25] = inputs.credentialCommitment;
        pubSignals[26] = inputs.platformId;

        return groth16.verifyProof(
            proof.a,
            proof.b,
            proof.c,
            pubSignals
        );
    }

    // ========== NULLIFIER MANAGEMENT ==========

    /**
     * @notice Check if a nullifier has been used
     */
    function isNullifierUsed(uint256 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /**
     * @notice Get verification result by ID
     */
    function getVerification(bytes32 verificationId) 
        external 
        view 
        returns (VerificationResult memory) 
    {
        return verificationHistory[verificationId];
    }

    // ========== BAN MANAGEMENT ==========

    /**
     * @notice Ban a user on this platform by recording their scope nullifier.
     *         scopeNullifier = Poseidon(userSecret, platformId) is stable across sessions.
     *         After banning, the user cannot generate a new valid proof on this platform.
     * @param scopeNullifier The banned user's stable scope nullifier
     */
    function banUser(uint256 scopeNullifier) external onlyAdmin {
        bannedScopeNullifiers[scopeNullifier] = true;
        emit UserBanned(scopeNullifier);
    }

    /**
     * @notice Unban a user (e.g. after appeal)
     */
    function unbanUser(uint256 scopeNullifier) external onlyAdmin {
        bannedScopeNullifiers[scopeNullifier] = false;
        emit UserUnbanned(scopeNullifier);
    }

    /**
     * @notice Check if a user is banned
     */
    function isUserBanned(uint256 scopeNullifier) external view returns (bool) {
        return bannedScopeNullifiers[scopeNullifier];
    }

    // ========== ISSUER MANAGEMENT ==========

    /**
     * @notice Register a credential commitment for a trusted issuer.
     *         Must be called by the admin on behalf of the issuer at credential issuance time.
     *         credentialCommitment = Poseidon(issuerPublicKey, attrs[0..7])
     */
    function registerCredential(uint256 issuerKey, uint256 credentialCommitment) external onlyAdmin {
        require(trustedIssuers[issuerKey], "ZKVerifier: Untrusted issuer");
        issuerCredentialRegistry[issuerKey][credentialCommitment] = true;
        emit CredentialRegistered(issuerKey, credentialCommitment);
    }

    /**
     * @notice Add a trusted issuer
     */
    function addTrustedIssuer(uint256 issuerKey) external onlyAdmin {
        trustedIssuers[issuerKey] = true;
        emit IssuerAdded(issuerKey);
    }

    /**
     * @notice Remove a trusted issuer
     */
    function removeTrustedIssuer(uint256 issuerKey) external onlyAdmin {
        trustedIssuers[issuerKey] = false;
        emit IssuerRemoved(issuerKey);
    }

    /**
     * @notice Check if issuer is trusted
     */
    function isIssuerTrusted(uint256 issuerKey) external view returns (bool) {
        return trustedIssuers[issuerKey];
    }

    // ========== ADMIN FUNCTIONS ==========

    /**
     * @notice Pause contract in emergency
     */
    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /**
     * @notice Transfer admin role
     */
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "ZKVerifier: Invalid admin");
        admin = newAdmin;
    }

}
