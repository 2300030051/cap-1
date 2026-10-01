const fs = require('fs');
const path = require('path');
const { ethers } = require('hardhat');

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying AcademicCredentialProof with account:', deployer.address);

  const AcademicCredentialProof = await ethers.getContractFactory('AcademicCredentialProof');
  const contract = await AcademicCredentialProof.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log('Contract deployed to:', contractAddress);

  const envPath = path.resolve(__dirname, '../../.env');
  const envLines = fs.existsSync(envPath)
    ? fs.readFileSync(envPath, 'utf8').split(/\r?\n/).filter(Boolean)
    : [];

  const filteredLines = envLines.filter(
    (line) => !line.startsWith('CREDENTIAL_CONTRACT_ADDRESS=')
  );

  filteredLines.push(`CREDENTIAL_CONTRACT_ADDRESS=${contractAddress}`);
  filteredLines.push('BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545');

  fs.writeFileSync(envPath, `${filteredLines.join('\n')}\n`);
  console.log(`Saved deployment address to ${envPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
