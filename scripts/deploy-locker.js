#!/usr/bin/env node
/**
 * MosooLocker Ethereum Deployment Script
 * Deploys the canonical MosooLocker settlement contract to Ethereum networks (Sepolia / Mainnet / Holesky).
 *
 * Usage:
 *   node scripts/deploy-locker.js --private-key <HEX_KEY> [--rpc <RPC_URL>] [--network sepolia]
 *   DEPLOYER_PRIVATE_KEY=<HEX_KEY> node scripts/deploy-locker.js
 */

const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

const DEFAULT_RPCS = {
  sepolia: [
    'https://ethereum-sepolia-rpc.publicnode.com',
    'https://rpc.sepolia.org',
    'https://rpc2.sepolia.org',
    'https://1rpc.io/sepolia'
  ],
  holesky: [
    'https://ethereum-holesky-rpc.publicnode.com',
    'https://rpc.holesky.ethpandaops.io'
  ],
  mainnet: [
    'https://ethereum-rpc.publicnode.com',
    'https://rpc.ankr.com/eth'
  ]
};

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    network: 'sepolia',
    rpc: null,
    privateKey: process.env.DEPLOYER_PRIVATE_KEY || null,
    attester: null,
    dryRun: false
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--network' && args[i + 1]) {
      options.network = args[++i];
    } else if (args[i] === '--rpc' && args[i + 1]) {
      options.rpc = args[++i];
    } else if (args[i] === '--private-key' && args[i + 1]) {
      options.privateKey = args[++i];
    } else if (args[i] === '--attester' && args[i + 1]) {
      options.attester = args[++i];
    } else if (args[i] === '--dry-run') {
      options.dryRun = true;
    }
  }

  return options;
}

async function getProvider(network, explicitRpc) {
  const candidateRpcs = explicitRpc ? [explicitRpc] : (DEFAULT_RPCS[network] || [DEFAULT_RPCS.sepolia[0]]);
  
  for (const rpcUrl of candidateRpcs) {
    try {
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      const net = await provider.getNetwork();
      console.log(`Connected to RPC: ${rpcUrl} (Chain ID: ${net.chainId})`);
      return provider;
    } catch (err) {
      console.warn(`RPC connection failed for ${rpcUrl}: ${err.message}. Trying next...`);
    }
  }
  throw new Error(`Failed to connect to any RPC endpoint for network ${network}`);
}

async function main() {
  const options = parseArgs();

  if (!options.privateKey) {
    console.error('Error: Private key required. Provide via --private-key <KEY> or DEPLOYER_PRIVATE_KEY environment variable.');
    process.exit(1);
  }

  let rawKey = options.privateKey.trim();
  if (!rawKey.startsWith('0x')) {
    rawKey = '0x' + rawKey;
  }

  const rootDir = path.resolve(__dirname, '..');
  const abiPath = path.join(rootDir, 'contracts', 'artifacts', 'MosooLocker.abi');
  const binPath = path.join(rootDir, 'contracts', 'artifacts', 'MosooLocker.bin');

  if (!fs.existsSync(abiPath) || !fs.existsSync(binPath)) {
    console.error(`Error: Compiled artifacts not found at ${abiPath} or ${binPath}`);
    process.exit(1);
  }

  const abi = JSON.parse(fs.readFileSync(abiPath, 'utf8'));
  let bin = fs.readFileSync(binPath, 'utf8').trim();
  if (!bin.startsWith('0x')) {
    bin = '0x' + bin;
  }

  console.log('--- MosooLocker Deployment Pipeline ---');
  console.log(`Target Network : ${options.network}`);

  const provider = await getProvider(options.network, options.rpc);
  const wallet = new ethers.Wallet(rawKey, provider);
  const deployerAddress = await wallet.getAddress();
  const attesterAuthority = options.attester || deployerAddress;

  console.log(`Deployer Address    : ${deployerAddress}`);
  console.log(`Attester Authority  : ${attesterAuthority}`);

  const balance = await provider.getBalance(deployerAddress);
  console.log(`Deployer Balance    : ${ethers.formatEther(balance)} ETH`);

  const factory = new ethers.ContractFactory(abi, bin, wallet);
  const deployTx = await factory.getDeployTransaction(attesterAuthority);

  const estimatedGas = await provider.estimateGas(deployTx);
  const feeData = await provider.getFeeData();
  const gasPrice = feeData.gasPrice || feeData.maxFeePerGas || ethers.parseUnits('1', 'gwei');
  const estimatedCost = estimatedGas * gasPrice;

  console.log(`Estimated Gas Units : ${estimatedGas.toString()}`);
  console.log(`Effective Gas Price : ${ethers.formatUnits(gasPrice, 'gwei')} Gwei`);
  console.log(`Estimated Cost      : ${ethers.formatEther(estimatedCost)} ETH`);

  if (balance < estimatedCost) {
    console.error(`Insufficient balance: Required ~${ethers.formatEther(estimatedCost)} ETH, available ${ethers.formatEther(balance)} ETH`);
    process.exit(1);
  }

  if (options.dryRun) {
    console.log('Dry run completed successfully. Skipping live broadcast.');
    return;
  }

  console.log('\nBroadcasting deployment transaction...');
  // Add 10% gas buffer to estimatedGas to prevent out-of-gas under block variation
  const gasLimit = (estimatedGas * 110n) / 100n;
  const contract = await factory.deploy(attesterAuthority, { gasLimit });

  console.log(`Transaction Hash    : ${contract.deploymentTransaction().hash}`);
  console.log('Waiting for block confirmation...');

  const receipt = await contract.deploymentTransaction().wait(1);
  const deployedAddress = await contract.getAddress();

  console.log('\n=== Deployment Successful ===');
  console.log(`Contract Address    : ${deployedAddress}`);
  console.log(`Block Number        : ${receipt.blockNumber}`);
  console.log(`Gas Used            : ${receipt.gasUsed.toString()}`);
  if (options.network === 'sepolia') {
    console.log(`Etherscan Link      : https://sepolia.etherscan.io/address/${deployedAddress}`);
    console.log(`Tx Explorer Link    : https://sepolia.etherscan.io/tx/${receipt.hash}`);
  }

  // Verify on-chain contract state
  console.log('\nVerifying on-chain contract parameters...');
  const deployedInstance = new ethers.Contract(deployedAddress, abi, provider);
  const owner = await deployedInstance.owner();
  const attester = await deployedInstance.attesterAuthority();
  const quorum = await deployedInstance.requiredQuorum();
  const isDeployerAttester = await deployedInstance.isAttester(attesterAuthority);
  const tokenAllowlist = await deployedInstance.tokenAllowlistEnabled();

  console.log(`  Contract Owner    : ${owner} (${owner === deployerAddress ? 'MATCH' : 'MISMATCH'})`);
  console.log(`  Attester Authority: ${attester} (${attester === attesterAuthority ? 'MATCH' : 'MISMATCH'})`);
  console.log(`  Quorum Requirement: ${quorum.toString()}`);
  console.log(`  Is Attester Active: ${isDeployerAttester}`);
  console.log(`  Allowlist Enabled : ${tokenAllowlist}`);

  // Write deployment artifact
  const deploymentsDir = path.join(rootDir, 'contracts', 'deployments');
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const manifest = {
    contractName: 'MosooLocker',
    network: options.network,
    chainId: (await provider.getNetwork()).chainId.toString(),
    address: deployedAddress,
    deployer: deployerAddress,
    attesterAuthority: attesterAuthority,
    transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed.toString(),
    deployedAt: new Date().toISOString(),
    rpcUsed: provider._getConnection().url || options.network
  };

  const manifestPath = path.join(deploymentsDir, `${options.network}.json`);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`\nDeployment manifest saved to: ${manifestPath}`);
}

main().catch((err) => {
  console.error('\nDeployment failed:', err);
  process.exit(1);
});
