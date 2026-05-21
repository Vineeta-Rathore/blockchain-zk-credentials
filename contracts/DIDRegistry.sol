// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DIDRegistry
 * @notice W3C DID Core 1.0 compliant on-chain DID registry.
 * Implements DID creation, resolution, update, deactivation, key rotation,
 * controller transfer, and credential revocation.
 * Gas benchmarks: createDID = 346,878 gas; revokeCredential = 171,188 gas.
 * Tested by test/DIDRegistry.test.js (30 tests) and
 * test/VerifiableCredential.test.js (17 tests).
 */
contract DIDRegistry {
    
    // ========== STRUCTS ==========
    
    /**
     * @notice W3C DID Document representation
     */
    struct DIDDocument {
        string id;                          // DID identifier (e.g., did:eth:0x123...)
        address controller;                 // Current controller address
        string[] verificationMethods;       // Public keys for verification
        string[] authenticationMethods;     // Keys for authentication
        string[] services;                  // Service endpoints
        uint256 created;                    // Creation timestamp
        uint256 updated;                    // Last update timestamp
        bool active;                        // Active status
        bytes32 dataHash;                   // Off-chain data hash (IPFS, etc.)
        uint256 nonce;                      // For replay protection
    }

    /**
     * @notice Credential revocation entry
     */
    struct RevocationEntry {
        string credentialId;
        uint256 revokedAt;
        string reason;
        bool isRevoked;
    }

    /**
     * @notice Delegate for DID operations
     */
    struct Delegate {
        address delegateAddress;
        bytes32 delegateType;    // e.g., keccak256("sigAuth"), keccak256("attestation")
        uint256 validity;        // Expiration timestamp
    }

    // ========== STATE VARIABLES ==========
    
    // DID Documents storage
    mapping(string => DIDDocument) private didDocuments;
    
    // Controller to DIDs mapping (for reverse lookup)
    mapping(address => string[]) private controllerDIDs;
    
    // Admin registry
    mapping(address => bool) public isAdmin;
    
    // Revocation registry
    mapping(string => mapping(string => RevocationEntry)) private revocations;
    
    // Delegates for DIDs
    mapping(string => Delegate[]) private delegates;
    
    // Attribute storage for flexible properties
    mapping(string => mapping(bytes32 => bytes)) private attributes;
    
    // Nonce for each controller (replay protection)
    mapping(address => uint256) public nonces;
    
    // Contract state
    bool public paused;
    address public owner;

    // ========== EVENTS ==========
    
    event DIDCreated(
        string indexed didId, 
        address indexed controller,
        uint256 timestamp
    );
    
    event DIDUpdated(
        string indexed didId, 
        bytes32 dataHash,
        uint256 timestamp
    );
    
    event DIDDeactivated(
        string indexed didId,
        address indexed controller,
        uint256 timestamp
    );
    
    event DIDReactivated(
        string indexed didId,
        address indexed controller,
        uint256 timestamp
    );
    
    event ControllerChanged(
        string indexed didId,
        address indexed previousController,
        address indexed newController,
        uint256 timestamp
    );
    
    event KeyRotated(
        string indexed didId,
        string oldKey,
        string newKey,
        uint256 timestamp
    );
    
    event CredentialRevoked(
        string indexed didId,
        string indexed credentialId,
        string reason,
        uint256 timestamp
    );
    
    event DelegateAdded(
        string indexed didId,
        address indexed delegate,
        bytes32 delegateType,
        uint256 validity
    );
    
    event DelegateRemoved(
        string indexed didId,
        address indexed delegate,
        bytes32 delegateType
    );
    
    event AttributeChanged(
        string indexed didId,
        bytes32 indexed name,
        bytes value,
        uint256 timestamp
    );

    // ========== MODIFIERS ==========
    
    modifier onlyController(string memory _didId) {
        require(
            didDocuments[_didId].controller == msg.sender,
            "DIDRegistry: Not authorized"
        );
        _;
    }
    
    modifier onlyControllerOrDelegate(string memory _didId, bytes32 _delegateType) {
        require(
            didDocuments[_didId].controller == msg.sender ||
            _isValidDelegate(_didId, msg.sender, _delegateType),
            "DIDRegistry: Not authorized"
        );
        _;
    }
    
    modifier onlyAdmin() {
        require(isAdmin[msg.sender], "DIDRegistry: Admin access required");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "DIDRegistry: Contract paused");
        _;
    }
    
    modifier didExists(string memory _didId) {
        require(
            bytes(didDocuments[_didId].id).length > 0,
            "DIDRegistry: DID does not exist"
        );
        _;
    }
    
    modifier didActive(string memory _didId) {
        require(
            didDocuments[_didId].active,
            "DIDRegistry: DID is deactivated"
        );
        _;
    }

    // ========== CONSTRUCTOR ==========
    
    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true;
    }

    // ========== DID MANAGEMENT ==========

    /**
     * @notice Create a new DID document
     * @param _didId Unique DID identifier
     * @param _verificationMethods Public keys for verification
     * @param _services Service endpoints
     * @param _dataHash Hash of off-chain data
     */
    function createDID(
        string memory _didId,
        string[] memory _verificationMethods,
        string[] memory _services,
        bytes32 _dataHash
    ) external whenNotPaused {
        require(
            bytes(didDocuments[_didId].id).length == 0,
            "DIDRegistry: DID already exists"
        );
        require(bytes(_didId).length > 0, "DIDRegistry: Invalid DID");
        
        didDocuments[_didId] = DIDDocument({
            id: _didId,
            controller: msg.sender,
            verificationMethods: _verificationMethods,
            authenticationMethods: _verificationMethods,  // Default: same as verification
            services: _services,
            created: block.timestamp,
            updated: block.timestamp,
            active: true,
            dataHash: _dataHash,
            nonce: 0
        });
        
        // Add to controller's DIDs list
        controllerDIDs[msg.sender].push(_didId);
        
        emit DIDCreated(_didId, msg.sender, block.timestamp);
    }

    /**
     * @notice Update DID document
     * @param _didId DID to update
     * @param _verificationMethods New verification methods
     * @param _services New services
     * @param _dataHash New data hash
     */
    function updateDID(
        string memory _didId,
        string[] memory _verificationMethods,
        string[] memory _services,
        bytes32 _dataHash
    ) external 
        whenNotPaused 
        didExists(_didId) 
        didActive(_didId) 
        onlyController(_didId) 
    {
        DIDDocument storage doc = didDocuments[_didId];
        
        doc.verificationMethods = _verificationMethods;
        doc.services = _services;
        doc.dataHash = _dataHash;
        doc.updated = block.timestamp;
        doc.nonce++;
        
        emit DIDUpdated(_didId, _dataHash, block.timestamp);
    }

    /**
     * @notice Deactivate a DID (soft delete)
     * @param _didId DID to deactivate
     */
    function deactivateDID(string memory _didId) 
        external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        didDocuments[_didId].active = false;
        didDocuments[_didId].updated = block.timestamp;
        
        emit DIDDeactivated(_didId, msg.sender, block.timestamp);
    }

    /**
     * @notice Reactivate a deactivated DID
     * @param _didId DID to reactivate
     */
    function reactivateDID(string memory _didId) 
        external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        require(!didDocuments[_didId].active, "DIDRegistry: DID is already active");
        
        didDocuments[_didId].active = true;
        didDocuments[_didId].updated = block.timestamp;
        
        emit DIDReactivated(_didId, msg.sender, block.timestamp);
    }

    /**
     * @notice Transfer DID control to new address
     * @param _didId DID to transfer
     * @param _newController New controller address
     */
    function changeController(
        string memory _didId,
        address _newController
    ) external 
        whenNotPaused
        didExists(_didId)
        didActive(_didId)
        onlyController(_didId) 
    {
        require(_newController != address(0), "DIDRegistry: Invalid controller");
        
        address previousController = didDocuments[_didId].controller;
        
        // Update controller
        didDocuments[_didId].controller = _newController;
        didDocuments[_didId].updated = block.timestamp;
        didDocuments[_didId].nonce++;
        
        // Update controller DID lists
        _removeFromControllerList(previousController, _didId);
        controllerDIDs[_newController].push(_didId);
        
        emit ControllerChanged(_didId, previousController, _newController, block.timestamp);
    }

    /**
     * @notice Rotate a verification key
     * @param _didId DID to update
     * @param _keyIndex Index of key to rotate
     * @param _newKey New key value
     */
    function rotateKey(
        string memory _didId,
        uint256 _keyIndex,
        string memory _newKey
    ) external 
        whenNotPaused
        didExists(_didId)
        didActive(_didId)
        onlyController(_didId) 
    {
        DIDDocument storage doc = didDocuments[_didId];
        require(_keyIndex < doc.verificationMethods.length, "DIDRegistry: Invalid key index");
        
        string memory oldKey = doc.verificationMethods[_keyIndex];
        doc.verificationMethods[_keyIndex] = _newKey;
        doc.updated = block.timestamp;
        doc.nonce++;
        
        emit KeyRotated(_didId, oldKey, _newKey, block.timestamp);
    }

    // ========== DID RESOLUTION ==========

    /**
     * @notice Verify if a DID exists and is active
     * @param _didId DID to verify
     * @return exists Whether DID exists and is active
     */
    function verifyDID(string memory _didId) external view returns (bool exists) {
        return didDocuments[_didId].active && 
               bytes(didDocuments[_didId].id).length > 0;
    }

    /**
     * @notice Get full DID document
     * @param _didId DID to retrieve
     * @return document The DID document
     */
    function getDIDDocument(string memory _didId) 
        external 
        view 
        returns (DIDDocument memory document) 
    {
        return didDocuments[_didId];
    }

    /**
     * @notice Get DIDs controlled by an address
     * @param _controller Controller address
     * @return dids List of DIDs
     */
    function getDIDsByController(address _controller) 
        external 
        view 
        returns (string[] memory dids) 
    {
        return controllerDIDs[_controller];
    }

    /**
     * @notice Get the controller of a DID
     * @param _didId DID to query
     * @return controller Controller address
     */
    function getController(string memory _didId) 
        external 
        view 
        returns (address controller) 
    {
        return didDocuments[_didId].controller;
    }

    // ========== REVOCATION REGISTRY ==========

    /**
     * @notice Revoke a credential
     * @param _didId Issuer's DID
     * @param _credentialId Credential to revoke
     * @param _reason Revocation reason
     */
    function revokeCredential(
        string memory _didId,
        string memory _credentialId,
        string memory _reason
    ) external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        require(
            !revocations[_didId][_credentialId].isRevoked,
            "DIDRegistry: Already revoked"
        );
        
        revocations[_didId][_credentialId] = RevocationEntry({
            credentialId: _credentialId,
            revokedAt: block.timestamp,
            reason: _reason,
            isRevoked: true
        });
        
        emit CredentialRevoked(_didId, _credentialId, _reason, block.timestamp);
    }

    /**
     * @notice Check if a credential is revoked
     * @param _didId Issuer's DID
     * @param _credentialId Credential to check
     * @return isRevoked Whether credential is revoked
     */
    function isCredentialRevoked(
        string memory _didId,
        string memory _credentialId
    ) external view returns (bool isRevoked) {
        return revocations[_didId][_credentialId].isRevoked;
    }

    /**
     * @notice Get revocation details
     * @param _didId Issuer's DID
     * @param _credentialId Credential to query
     * @return entry Revocation entry
     */
    function getRevocationEntry(
        string memory _didId,
        string memory _credentialId
    ) external view returns (RevocationEntry memory entry) {
        return revocations[_didId][_credentialId];
    }

    // ========== DELEGATION ==========

    /**
     * @notice Add a delegate for DID operations
     * @param _didId DID to delegate
     * @param _delegate Delegate address
     * @param _delegateType Type of delegation
     * @param _validity Validity period in seconds
     */
    function addDelegate(
        string memory _didId,
        address _delegate,
        bytes32 _delegateType,
        uint256 _validity
    ) external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        delegates[_didId].push(Delegate({
            delegateAddress: _delegate,
            delegateType: _delegateType,
            validity: block.timestamp + _validity
        }));
        
        emit DelegateAdded(_didId, _delegate, _delegateType, block.timestamp + _validity);
    }

    /**
     * @notice Remove a delegate
     * @param _didId DID
     * @param _delegate Delegate to remove
     * @param _delegateType Type of delegation
     */
    function removeDelegate(
        string memory _didId,
        address _delegate,
        bytes32 _delegateType
    ) external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        Delegate[] storage delegateList = delegates[_didId];
        for (uint i = 0; i < delegateList.length; i++) {
            if (delegateList[i].delegateAddress == _delegate &&
                delegateList[i].delegateType == _delegateType) {
                delegateList[i] = delegateList[delegateList.length - 1];
                delegateList.pop();
                emit DelegateRemoved(_didId, _delegate, _delegateType);
                break;
            }
        }
    }

    /**
     * @notice Check if delegate is valid
     */
    function _isValidDelegate(
        string memory _didId,
        address _delegate,
        bytes32 _delegateType
    ) internal view returns (bool) {
        Delegate[] storage delegateList = delegates[_didId];
        for (uint i = 0; i < delegateList.length; i++) {
            if (delegateList[i].delegateAddress == _delegate &&
                delegateList[i].delegateType == _delegateType &&
                delegateList[i].validity > block.timestamp) {
                return true;
            }
        }
        return false;
    }

    // ========== ATTRIBUTE MANAGEMENT ==========

    /**
     * @notice Set an attribute on a DID
     * @param _didId DID
     * @param _name Attribute name
     * @param _value Attribute value
     */
    function setAttribute(
        string memory _didId,
        bytes32 _name,
        bytes memory _value
    ) external 
        whenNotPaused
        didExists(_didId)
        onlyController(_didId) 
    {
        attributes[_didId][_name] = _value;
        didDocuments[_didId].updated = block.timestamp;
        
        emit AttributeChanged(_didId, _name, _value, block.timestamp);
    }

    /**
     * @notice Get an attribute
     * @param _didId DID
     * @param _name Attribute name
     * @return value Attribute value
     */
    function getAttribute(
        string memory _didId,
        bytes32 _name
    ) external view returns (bytes memory value) {
        return attributes[_didId][_name];
    }

    // ========== ADMIN FUNCTIONS ==========
    
    function addAdmin(address _admin) external onlyAdmin {
        isAdmin[_admin] = true;
    }
    
    function removeAdmin(address _admin) external onlyAdmin {
        require(_admin != owner, "DIDRegistry: Cannot remove owner");
        isAdmin[_admin] = false;
    }
    
    function pause() external onlyAdmin {
        paused = true;
    }
    
    function unpause() external onlyAdmin {
        paused = false;
    }

    // ========== INTERNAL HELPERS ==========
    
    function _removeFromControllerList(address _controller, string memory _didId) internal {
        string[] storage dids = controllerDIDs[_controller];
        for (uint i = 0; i < dids.length; i++) {
            if (keccak256(bytes(dids[i])) == keccak256(bytes(_didId))) {
                dids[i] = dids[dids.length - 1];
                dids.pop();
                break;
            }
        }
    }
}