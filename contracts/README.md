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

- **Trust Model & Security Guarantees**:
  - **Asymmetric Hybrid Trust Model**:
    - **Inbound (ETH -> LEZ)**: 100% trustless on-chain consensus tracking and MPT receipt inclusion proof verification inside the RISC Zero zkVM on LEZ.
    - **Outbound (LEZ -> ETH)**: Multi-layered witness-attested committee settlement with defense-in-depth:
      1. Multi-signer committee quorum (`unlockETHWithQuorum`, `unlockERC20WithQuorum`) requiring $M$-of-$N$ threshold signatures from authorized committee members.
      2. EIP-712 structured data signing with strict domain separation and contract address binding.
      3. Replay nullifier registry (`executedBurns[burnId]`).
      4. Rolling 24-hour daily withdrawal limits (`dailyWithdrawalLimitETH`, `dailyWithdrawalLimitERC20`) bounding maximum outflow velocity.
      5. Mandatory 24-hour timelock queue for large withdrawals ($\ge 10$ ETH).
      6. Permanent Guardian & Owner cancellation veto (`cancelledBurns[burnId]`), strictly preventing re-queueing of vetoed withdrawals.
      7. Inviolable 24-hour timelock on updating `attesterAuthority` or modifying committee quorum.
    - **Trust Boundary Note**: Outbound withdrawals rely on the threshold attester committee ($M$-of-$N$ quorum). Verifying LEZ consensus and zk-state proofs directly on Ethereum L1 without attesters is slated for future protocol phases (which requires deploying an on-chain zk-SNARK / Groth16 verifier contract on Ethereum).
  - `ReentrancyGuard` protection against recursive calls across deposit and unlock flows.
  - Safe token transfer checks: strict contract existence checks (`token.code.length > 0`) preventing phantom transfers on EOAs.
  - Fee-on-transfer protection via before/after balance differentials on `depositERC20`.
  - Signature malleability protection: strict EIP-2 upper-bound checks on `s` values.
  - 1:1 asset backing invariance: `totalLockedETH == active_mETH_supply_on_LEZ`.
  - Vault accounting invariants: checks `totalLockedETH < amount || address(this).balance < amount` prior to ETH release.
  - Direct transfer protection: `receive()` strictly reverts to prevent unindexed ether desync.
  - Dual-role emergency controls: `emergencyPause()` callable by designated `guardian` or `owner`.
  - Two-step ownership transfers: `transferOwnership` + `acceptOwnership` to guard against operational misdirection.

## EVM Verification & Foundry Testing

The contract test suite is written in Solidity under [`test/MosooLocker.t.sol`](./test/MosooLocker.t.sol) and configured via [`foundry.toml`](../foundry.toml).

```console
# Run Solidity unit and fuzz tests with Foundry
forge test -vvv
```

## Canonical Deployments

| Network | Contract | Address | Transaction Hash | Explorer |
| :--- | :--- | :--- | :--- | :--- |
| **Ethereum Sepolia** | `MosooLocker` | `0x74625D146B8d9413F3c3976B323d94A739be7856` | `0x1b492d89631c7fb398008285e777781d95f48c1a07c9d6ca2d6be5459941b28b` | [Sepolia Etherscan](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) |

