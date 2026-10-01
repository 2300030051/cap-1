const path = require('path');
require('@nomicfoundation/hardhat-chai-matchers');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const DEFAULT_HARDHAT_MNEMONIC = 'test test test test test test test test test test test junk';

module.exports = {
  solidity: '0.8.28',
  defaultNetwork: 'hardhat',
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts'
  },
  networks: {
    hardhat: {
      chainId: 1337
    },
    localhost: {
      url: process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545',
      accounts: process.env.BLOCKCHAIN_PRIVATE_KEY
        ? [process.env.BLOCKCHAIN_PRIVATE_KEY]
        : { mnemonic: DEFAULT_HARDHAT_MNEMONIC }
    }
  }
};
