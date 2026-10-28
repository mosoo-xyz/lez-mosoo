#!/usr/bin/env node
/**
 * MosooLocker ETH Deposit Script
 * Locks Sepolia ETH into MosooLocker.sol targeting a LEZ recipient address.
 *
 * Usage:
 *   node scripts/deposit-eth.js --private-key <HEX_KEY> [--amount 0.01] [--recipient <HEX_OR_BASE58>]
 *   DEPLOYER_PRIVATE_KEY=<HEX_KEY> node scripts/deposit-eth.js
 */

const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

const SEPOLIA_RPCS = [
  'https://ethereum-sepolia-rpc.publicnode.com',
  'https://1rpc.io/sepolia'
];

const LOCKER_ADDRESS = '0x74625D146B8d9413F3c3976B323d94A739be7856';

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    amount: '0.01',
    privateKey: process.env.DEPLOYER_PRIVATE_KEY || process.env.PRIVATE_KEY || null,
    recipient: null,
    rpc: null
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--private-key' && args[i + 1]) {
      options.privateKey = args[++i];
    } else if (args[i] === '--amount' && args[i + 1]) {
      options.amount = args[++i];
    } else if (args[i] === '--recipient' && args[i + 1]) {
      options.recipient = args[++i];
    } else if (args[i] === '--rpc' && args[i + 1]) {
      options.rpc = args[++i];
    }
  }

  // Fallback to local wallet.json recipient if not provided
  if (!options.recipient) {
    const walletPath = path.join(__dirname, 'wallet.json');
    if (fs.existsSync(walletPath)) {
      try {
        const wData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
        options.recipient = wData.publicKeyHex;
      } catch (_) {}
    }
  }

  if (!options.recipient) {
    // Default fallback canonical testnet recipient
    options.recipient = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  }

  return options;
}

async function getProvider(explicitRpc) {
  const candidates = explicitRpc ? [explicitRpc] : SEPOLIA_RPCS;
  for (const rpcUrl of candidates) {
    try {
      const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true });
      const net = await provider.getNetwork();
      if (Number(net.chainId) === 11155111) {
        return provider;
      }
    } catch (_) {}
  }
  throw new Error('Failed connecting to any Ethereum Sepolia RPC endpoint.');
}

async function main() {
  const options = parseArgs();

  console.log('='.repeat(75));
  console.log('MOSOO ETH TO LEZ ON-CHAIN DEPOSIT TOOL (SEPOLIA)');
  console.log('='.repeat(75));
  console.log(`MosooLocker Contract : ${LOCKER_ADDRESS}`);
  console.log(`Deposit Amount       : ${options.amount} ETH`);
  console.log(`Target LEZ Recipient : ${options.recipient}`);

  if (!options.privateKey) {
    console.log('\n[!] Notice: No private key provided.');
    console.log('To execute this live on-chain, run:');
    console.log('  node scripts/deposit-eth.js --private-key <YOUR_SEPOLIA_PRIVATE_KEY> --amount ' + options.amount);
    console.log('or:');
    console.log('  $env:DEPLOYER_PRIVATE_KEY="<YOUR_KEY>"; node scripts/deposit-eth.js');
    console.log('='.repeat(75));
    process.exit(0);
  }

  let rawKey = options.privateKey.trim();
  if (!rawKey.startsWith('0x')) rawKey = '0x' + rawKey;

  const provider = await getProvider(options.rpc);
  const signer = new ethers.Wallet(rawKey, provider);
  const signerAddress = await signer.getAddress();
  const balance = await provider.getBalance(signerAddress);

  console.log(`Sender Address       : ${signerAddress}`);
  console.log(`Sender Balance       : ${ethers.formatEther(balance)} ETH`);

  const amountWei = ethers.parseEther(options.amount);
  if (balance < amountWei) {
    console.error(`[-] Error: Insufficient balance. Need ${options.amount} ETH + gas.`);
    process.exit(1);
  }

  // Format recipient to bytes32
  let recipientBytes32 = options.recipient;
  if (!recipientBytes32.startsWith('0x')) recipientBytes32 = '0x' + recipientBytes32;
  recipientBytes32 = ethers.zeroPadValue(recipientBytes32, 32);

  const abi = [
    'function depositETH(bytes32 lezRecipient) external payable returns (uint64 nonce)',
    'function totalLockedETH() external view returns (uint256)',
    'event DepositETH(address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 indexed nonce)'
  ];

  const contract = new ethers.Contract(LOCKER_ADDRESS, abi, signer);

  console.log('\n[+] Broadcasting deposit transaction to Sepolia...');
  const tx = await contract.depositETH(recipientBytes32, { value: amountWei });
  console.log(`[+] Tx Hash Broadcasted: ${tx.hash}`);
  console.log('[-] Waiting for block confirmation...');

  const receipt = await tx.wait(1);
  console.log(`[+] Confirmed in Block: ${receipt.blockNumber} (Status: ${receipt.status === 1 ? 'SUCCESS' : 'FAILED'})`);
  console.log(`[+] Gas Used: ${receipt.gasUsed.toString()}`);

  const newTotal = await contract.totalLockedETH();
  console.log(`[+] Updated Total Locked ETH in Vault: ${ethers.formatEther(newTotal)} ETH`);
  console.log('\nView on Sepolia Etherscan:');
  console.log(`  https://sepolia.etherscan.io/tx/${tx.hash}`);
  console.log('='.repeat(75));
}

main().catch(err => {
  console.error('[-] Fatal error:', err.message);
  process.exit(1);
});
