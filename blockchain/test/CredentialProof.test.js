const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('AcademicCredentialProof', function () {
  let contract;

  beforeEach(async function () {
    const AcademicCredentialProof = await ethers.getContractFactory('AcademicCredentialProof');
    contract = await AcademicCredentialProof.deploy();
    await contract.waitForDeployment();
  });

  it('issues and validates a credential', async function () {
    const credentialId = 'cred-1';
    const credentialHash = ethers.keccak256(ethers.toUtf8Bytes('Alice|BSc|University|2026|2026-05-01T00:00:00.000Z'));

    await contract.issueCredential(credentialId, credentialHash);

    const stored = await contract.getCredential(credentialId);
    expect(stored[0]).to.not.equal(ethers.ZeroHash);
    expect(stored[1]).to.equal(credentialHash);
    expect(await contract.isCredentialValid(credentialId, credentialHash)).to.equal(true);
  });

  it('prevents duplicate issuance and revocation flow', async function () {
    const credentialId = 'cred-2';
    const credentialHash = ethers.keccak256(ethers.toUtf8Bytes('Bob|MSc|College|2027|2027-05-01T00:00:00.000Z'));

    await contract.issueCredential(credentialId, credentialHash);
    await expect(contract.issueCredential(credentialId, credentialHash))
      .to.be.revertedWith('Credential already exists.');

    await contract.revokeCredential(credentialId);
    expect(await contract.isCredentialValid(credentialId, credentialHash)).to.equal(false);
  });
});
