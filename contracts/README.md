# Mosoo Ethereum Escrow & Settlement Contracts

This directory contains the canonical Solidity contracts for the Mosoo Light Client Bridge connecting Ethereum and the Logos Execution Zone (LEZ).

## Contracts Overview

### [`MosooLocker.sol`](./MosooLocker.sol)
The core vault and settlement contract deployed on Ethereum (Mainnet / Sepolia / Holesky).

- **Deposit Path (ETH -> LEZ)**:
  - Users call `depositETH(bytes32 lezRecipient)` with native ETH.
  - Locks ETH in the contract vault.
  - Emits `DepositETH(address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 indexed nonce)`.
  - The transaction receipt is included in the Ethereum execution block.
  - The Mosoo zkVM Light Client on LEZ verifies the receipt via Merkle-Patricia Trie (MPT) inclusion proofs and mints 1:1 synthetic `mETH` to `lezRecipient`.

- **Burn & Unlock Path (LEZ -> ETH)**:
  - Users call `burn_meth` on LEZ, which burns synthetic `mETH` and produces an on-chain `BurnReceipt`.
  - The user/relayer calls `unlockETH(bytes32 burnId, uint256 amount, address payable recipient, ...)` on Ethereum.
  - Strictly prevents replay attacks using the `executedBurns` nullifier registry (`mapping(bytes32 => bool)`).
  - Releases locked ETH directly to `recipient`.

- **Security Guarantees**:
  - `ReentrancyGuard` protection against recursive calls.
  - Cryptographic nullifiers prevent double-spending on both chains.
  - 1:1 asset backing invariance: `totalLockedETH == active_mETH_supply_on_LEZ`.
  - Emergency pausing mechanism controlled by owner.
