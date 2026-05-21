// Unit tests for DIDRegistry.sol: lifecycle, key rotation, revocation, and edge cases.

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("DIDRegistry", function () {
  let didRegistry;
  let owner, user1, user2, verifier;

  beforeEach(async function () {
    [owner, user1, user2, verifier] = await ethers.getSigners();

    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    didRegistry = await DIDRegistry.deploy();
    await didRegistry.deployed();
  });

  describe("Deployment", function () {
    it("Should set the deployer as admin", async function () {
      expect(await didRegistry.isAdmin(owner.address)).to.be.true;
    });

    it("Should have correct initial state", async function () {
      expect(await didRegistry.isAdmin(user1.address)).to.be.false;
    });

    it("Should set deployer as owner", async function () {
      expect(await didRegistry.owner()).to.equal(owner.address);
    });
  });

  describe("DID Creation", function () {
    it("Should create a new DID successfully", async function () {
      const didId = "did:example:123456789";
      const verificationMethods = ["key1", "key2"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test data"));

      await expect(
        didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash)
      ).to.emit(didRegistry, "DIDCreated");

      const didDoc = await didRegistry.getDIDDocument(didId);
      expect(didDoc.id).to.equal(didId);
      expect(didDoc.controller).to.equal(user1.address);
      expect(didDoc.active).to.be.true;
      expect(didDoc.verificationMethods[0]).to.equal("key1");
    });

    it("Should prevent duplicate DID creation", async function () {
      const didId = "did:example:duplicate";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user2).createDID(didId, verificationMethods, services, dataHash)
      ).to.be.revertedWith("DIDRegistry: DID already exists");
    });

    it("Should handle multiple DIDs from same user", async function () {
      const didId1 = "did:example:user1-first";
      const didId2 = "did:example:user1-second";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));

      await didRegistry.connect(user1).createDID(didId1, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).createDID(didId2, verificationMethods, services, dataHash);

      expect(await didRegistry.verifyDID(didId1)).to.be.true;
      expect(await didRegistry.verifyDID(didId2)).to.be.true;
    });
  });

  describe("DID Updates", function () {
    beforeEach(async function () {
      const didId = "did:example:update-test";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("initial"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
    });

    it("Should allow controller to update DID", async function () {
      const didId = "did:example:update-test";
      const newVerificationMethods = ["key1", "key2"];
      const newServices = ["service1", "service2"];
      const newDataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("updated"));

      await expect(
        didRegistry.connect(user1).updateDID(didId, newVerificationMethods, newServices, newDataHash)
      ).to.emit(didRegistry, "DIDUpdated");

      const didDoc = await didRegistry.getDIDDocument(didId);
      expect(didDoc.verificationMethods.length).to.equal(2);
      expect(didDoc.services.length).to.equal(2);
    });

    it("Should prevent unauthorized updates", async function () {
      const didId = "did:example:update-test";
      const newVerificationMethods = ["malicious-key"];
      const newServices = ["malicious-service"];
      const newDataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("malicious"));

      await expect(
        didRegistry.connect(user2).updateDID(didId, newVerificationMethods, newServices, newDataHash)
      ).to.be.revertedWith("DIDRegistry: Not authorized");
    });

    it("Should prevent non-controller from deactivating DID", async function () {
      const didId = "did:example:update-test";

      await expect(
        didRegistry.connect(user2).deactivateDID(didId)
      ).to.be.revertedWith("DIDRegistry: Not authorized");
    });
  });

  describe("DID Verification", function () {
    it("Should return false for non-existent DID", async function () {
      const nonExistentDID = "did:example:nonexistent";
      expect(await didRegistry.verifyDID(nonExistentDID)).to.be.false;
    });

    it("Should return true for active DID", async function () {
      const didId = "did:example:active";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("active"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      expect(await didRegistry.verifyDID(didId)).to.be.true;
    });

    it("Should return false for deactivated DID", async function () {
      const didId = "did:example:deactivated";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("deactivated"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).deactivateDID(didId);

      expect(await didRegistry.verifyDID(didId)).to.be.false;
    });
  });

  describe("Controller Management", function () {
    it("Should transfer DID control", async function () {
      const didId = "did:example:transfer-test";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("transfer"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user1).changeController(didId, user2.address)
      ).to.emit(didRegistry, "ControllerChanged");

      expect(await didRegistry.getController(didId)).to.equal(user2.address);
    });

    it("Should get DIDs by controller", async function () {
      const didId1 = "did:example:lookup-1";
      const didId2 = "did:example:lookup-2";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("lookup"));

      await didRegistry.connect(user1).createDID(didId1, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).createDID(didId2, verificationMethods, services, dataHash);

      const dids = await didRegistry.getDIDsByController(user1.address);
      expect(dids.length).to.equal(2);
      expect(dids).to.include(didId1);
      expect(dids).to.include(didId2);
    });

    it("Should prevent non-controller from transferring DID control", async function () {
      const didId = "did:example:transfer-unauth";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("transfer-unauth"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user2).changeController(didId, user2.address)
      ).to.be.revertedWith("DIDRegistry: Not authorized");
    });
  });

  describe("Key Rotation", function () {
    it("Should rotate verification key", async function () {
      const didId = "did:example:key-rotate";
      const verificationMethods = ["oldKey1", "oldKey2"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("keys"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user1).rotateKey(didId, 0, "newKey1")
      ).to.emit(didRegistry, "KeyRotated");

      const didDoc = await didRegistry.getDIDDocument(didId);
      expect(didDoc.verificationMethods[0]).to.equal("newKey1");
      expect(didDoc.verificationMethods[1]).to.equal("oldKey2");
    });

    it("Should prevent non-controller from rotating verification key", async function () {
      const didId = "did:example:rotate-unauth";
      const verificationMethods = ["key1"];
      const services = [];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("rotate-unauth"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user2).rotateKey(didId, 0, "maliciousKey")
      ).to.be.revertedWith("DIDRegistry: Not authorized");
    });
  });

  describe("Revocation Registry", function () {
    it("Should revoke a credential", async function () {
      const didId = "did:example:issuer";
      const credentialId = "cred:123456";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("issuer"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      await expect(
        didRegistry.connect(user1).revokeCredential(didId, credentialId, "Key compromised")
      ).to.emit(didRegistry, "CredentialRevoked");

      expect(await didRegistry.isCredentialRevoked(didId, credentialId)).to.be.true;
    });

    it("Should not revoke same credential twice", async function () {
      const didId = "did:example:issuer2";
      const credentialId = "cred:789";
      const verificationMethods = ["key1"];
      const services = [];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("issuer2"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).revokeCredential(didId, credentialId, "Expired");

      await expect(
        didRegistry.connect(user1).revokeCredential(didId, credentialId, "Double revoke")
      ).to.be.revertedWith("DIDRegistry: Already revoked");
    });

    it("Should allow credential revocation after issuer DID is deactivated", async function () {
      const didId = "did:example:post-deactivation-revoke";
      const credentialId = "cred:post-deactivation";
      const verificationMethods = ["key1"];
      const services = [];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("post-deactivation"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).deactivateDID(didId);
      expect(await didRegistry.verifyDID(didId)).to.be.false;

      // revokeCredential has no didActive modifier — controller retains revocation rights
      await expect(
        didRegistry.connect(user1).revokeCredential(didId, credentialId, "Post-deactivation revocation")
      ).to.emit(didRegistry, "CredentialRevoked");
      expect(await didRegistry.isCredentialRevoked(didId, credentialId)).to.be.true;
    });

    it("Should revert when revoking credential on non-existent DID", async function () {
      await expect(
        didRegistry.connect(user1).revokeCredential(
          "did:example:does-not-exist", "cred:123", "reason"
        )
      ).to.be.revertedWith("DIDRegistry: DID does not exist");
    });
  });

  describe("Admin Functions", function () {
    it("Should allow admin to add new admin", async function () {
      await didRegistry.connect(owner).addAdmin(user1.address);
      expect(await didRegistry.isAdmin(user1.address)).to.be.true;
    });

    it("Should prevent non-admin from adding admin", async function () {
      await expect(
        didRegistry.connect(user1).addAdmin(user2.address)
      ).to.be.revertedWith("DIDRegistry: Admin access required");
    });

    it("Should allow admin to pause contract", async function () {
      await didRegistry.connect(owner).pause();
      expect(await didRegistry.paused()).to.be.true;
    });

    it("Should prevent non-admin from pausing contract", async function () {
      await expect(
        didRegistry.connect(user1).pause()
      ).to.be.revertedWith("DIDRegistry: Admin access required");
    });

    it("Should revert DID creation when contract is paused", async function () {
      await didRegistry.connect(owner).pause();

      await expect(
        didRegistry.connect(user1).createDID(
          "did:example:paused-test",
          ["key1"],
          [],
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes("paused"))
        )
      ).to.be.revertedWith("DIDRegistry: Contract paused");
    });
  });

  describe("Gas Optimization", function () {
    it("Should use reasonable gas for DID creation", async function () {
      const didId = "did:example:gas-test";
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("gas-test"));

      const tx = await didRegistry.connect(user1).createDID(
        didId, verificationMethods, services, dataHash
      );
      const receipt = await tx.wait();

      console.log(`Gas used for DID creation: ${receipt.gasUsed.toString()}`);
      expect(receipt.gasUsed.toNumber()).to.be.lessThan(500000);
    });
  });

  describe("Edge Cases", function () {
    it("Should handle empty verification methods", async function () {
      const didId = "did:example:empty-methods";
      const verificationMethods = [];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("empty"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);

      const didDoc = await didRegistry.getDIDDocument(didId);
      expect(didDoc.verificationMethods.length).to.equal(0);
      expect(didDoc.active).to.be.true;
    });

    it("Should handle long DID strings", async function () {
      const didId = "did:example:" + "a".repeat(100);
      const verificationMethods = ["key1"];
      const services = ["service1"];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("long"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      expect(await didRegistry.verifyDID(didId)).to.be.true;
    });

    it("Should reactivate deactivated DID", async function () {
      const didId = "did:example:reactivate";
      const verificationMethods = ["key1"];
      const services = [];
      const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("reactivate"));

      await didRegistry.connect(user1).createDID(didId, verificationMethods, services, dataHash);
      await didRegistry.connect(user1).deactivateDID(didId);
      expect(await didRegistry.verifyDID(didId)).to.be.false;

      await didRegistry.connect(user1).reactivateDID(didId);
      expect(await didRegistry.verifyDID(didId)).to.be.true;
    });
  });
});

// Helper function
async function getBlockTimestamp() {
  const block = await ethers.provider.getBlock("latest");
  return block.timestamp;
}