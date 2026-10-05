const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const artifactPath = path.join(
  __dirname,
  'blockchain',
  'artifacts',
  'contracts',
  'AcademicCredentialProof.sol',
  'AcademicCredentialProof.json'
);

function normalizeHash(hash) {
  if (typeof hash !== 'string') {
    throw new Error('A valid credential hash is required.');
  }

  const withoutPrefix = hash.replace(/^0x/i, '').toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(withoutPrefix)) {
    throw new Error('Credential hash must be a 32-byte SHA-256 hex string.');
  }

  return `0x${withoutPrefix}`;
}

function getProvider() {
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545';
  return new ethers.JsonRpcProvider(rpcUrl);
}

function getWallet() {
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY;

  if (!privateKey) {
    throw new Error('BLOCKCHAIN_PRIVATE_KEY is not set.');
  }

  return new ethers.Wallet(privateKey, getProvider());
}

function getContract(signer) {
  const contractAddress = process.env.CREDENTIAL_CONTRACT_ADDRESS;

  if (!contractAddress) {
    throw new Error('CREDENTIAL_CONTRACT_ADDRESS is not set.');
  }

  if (!fs.existsSync(artifactPath)) {
    throw new Error('Blockchain contract artifacts were not found. Run the Hardhat compile step first.');
  }

  const artifact = require(artifactPath);
  return new ethers.Contract(contractAddress, artifact.abi, signer || getProvider());
}

async function anchorCredential({ id, hash }) {
  const wallet = getWallet();
  const contract = getContract(wallet);
  const chainHash = normalizeHash(hash);

  const transaction = await contract.issueCredential(id, chainHash);
  const receipt = await transaction.wait();

  if (!receipt || receipt.status !== 1) {
    throw new Error('Blockchain anchoring transaction was not successful.');
  }

  return {
    contractAddress: await contract.getAddress(),
    transactionHash: receipt?.hash || transaction.hash,
    blockNumber: receipt?.blockNumber || null,
    status: 'ANCHORED'
  };
}

async function revokeCredentialOnChain({ id }) {
  const wallet = getWallet();
  const contract = getContract(wallet);

  const transaction = await contract.revokeCredential(id);
  const receipt = await transaction.wait();

  if (!receipt || receipt.status !== 1) {
    throw new Error('Blockchain revocation transaction was not successful.');
  }

  return {
    contractAddress: await contract.getAddress(),
    transactionHash: receipt?.hash || transaction.hash,
    blockNumber: receipt?.blockNumber || null,
    status: 'REVOKED'
  };
}

async function getCredentialOnChain(id) {
  const contract = getContract();

  try {
    const record = await contract.getCredential(id);

    if (!record || record[0] === ethers.ZeroHash) {
      return null;
    }

    return {
      credentialIdHash: record[0],
      credentialHash: record[1],
      issuer: record[2],
      issuedAt: Number(record[3]),
      revoked: Boolean(record[4])
    };
  } catch (error) {
    return null;
  }
}

async function checkBlockchainValidity({ id, hash }) {
  try {
    const contract = getContract();
    const record = await contract.getCredential(id);

    if (!record || record[0] === ethers.ZeroHash) {
      return {
        exists: false,
        result: 'BLOCKCHAIN_VERIFICATION_FAILED',
        message: 'No blockchain record found for this credential.'
      };
    }

    const chainHash = normalizeHash(record[1]);
    const providedHash = normalizeHash(hash);
    const matchesHash = chainHash.toLowerCase() === providedHash.toLowerCase();
    const revoked = Boolean(record[4]);

    return {
      exists: true,
      revoked,
      matchesHash,
      issuer: record[2],
      issuedAt: Number(record[3]),
      result: revoked ? 'REVOKED' : matchesHash ? 'VALID' : 'INVALID'
    };
  } catch (error) {
    return {
      exists: false,
      result: 'BLOCKCHAIN_VERIFICATION_FAILED',
      message: 'Blockchain verification is unavailable.'
    };
  }
}

module.exports = {
  normalizeHash,
  getProvider,
  getWallet,
  getContract,
  anchorCredential,
  revokeCredentialOnChain,
  getCredentialOnChain,
  checkBlockchainValidity
};
