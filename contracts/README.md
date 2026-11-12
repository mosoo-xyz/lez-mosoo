# Mosoo Ethereum Escrow & Settlement Contracts

This directory contains the canonical Solidity contracts for the Mosoo Light Client Bridge connecting Ethereum and the Logos Execution Zone (LEZ).

## Contracts Overview

### [`MosooLocker.sol`](./MosooLocker.sol)
The core vault and settlement contract deployed on Ethereum (Mainnet / Sepolia / Holesky).

- **Deposit Path (ETH / ERC-20 -> LEZ)**:
  - **Privacy-Preserving Shielded Pool (RFP-022 Default Recommended)**:
    - Users call `depositShieldedETH(bytes32 commitment)` or `depositShieldedERC20(address token, uint256 amount, bytes32 commitment)`.
    - Inserts `commitment` into a depth-20 incremental Merkle tree (`currentCommitmentRoot`, historical `knownDepositRoots`) and emits `DepositCommitted(commitment, token, amount, leafIndex, newRoot, nonce)` with **no `sender` and no `lezRecipient`**.
    - Optional governance hardening (`setShieldedDepositsOnly(true)` and `setStrictFixedDenominationMode(true)`) prevents legacy cleartext deposits and enforces fixed amount pools (`0.01`, `0.1`, `1`, `10` ETH) to eliminate deposit amount correlation.
  - **Legacy Cleartext Deposit Path (Opt-Out via `shieldedDepositsOnly`)**:
    - Users call `depositETH(bytes32 lezRecipient)` or `depositERC20(address token, uint256 amount, bytes32 lezRecipient)`.
    - Emits `DepositETH` / `DepositERC20` containing `lezRecipient`.
  - The transaction receipt is included in the Ethereum execution block, verified via Merkle-Patricia Trie (MPT) inclusion proofs inside `mosoo-core` / `mosoo-guest`, and claimed privately on LEZ using the commitment preimage (`secret`, `nullifier_secret`) and unlinkable `claim_nullifier`.

- **Burn & Unlock Path (LEZ -> ETH / ERC-20)**:
  - **Trustless RISC Zero Outbound ZK Unlock (`MosooZkBurnVerifier.sol` + `MosooLocker.unlockShieldedWithZkProof`)**:
    - `MosooZkBurnVerifier.sol` (`5,996 B`) implements `IRiscZeroVerifier` verification (`sha256(journal)` + immutable `outboundBurnImageId`, `lezStateTransitionImageId`, & `expectedSourceInstance`), permissionless chained LEZ state-root advancement (`advanceLezStateRootWithProof`, `224`-byte ABI) with non-launderable pure-ZK lineage tracking (`isPureZkRoot` & `latestPureZkRoot` rollback on `enableZkStrictMode`), strict upper-zero ABI padding validation (`288`-byte `OutboundBurnJournal`), and an irreversible `enableZkStrictMode()` latch.
    - `MosooLocker.unlockShieldedWithZkProof(bytes seal, bytes journal)` (`24,374 B` EIP-170 runtime bytecode) delegates verification to the timelocked `zkBurnVerifier` (`proposeZkBurnVerifier` / `executeZkBurnVerifier`) and enforces replay nullifiers, guardian vetoes, rolling daily caps, and 24h large-withdrawal delays. *(Pending live `IRiscZeroVerifier` router wiring and Sepolia redeployment; live Sepolia v4 `0xF94eA0F9...` currently uses the `2-of-2` attester path.)*
  - **Shielded Attester Quorum Unlock (RFP-022)**:
    - `unlockShieldedETH(bytes32 burnNullifier, bytes32 sourceInstance, uint256 amount, address payable recipient, bytes[] signatures)` and `unlockShieldedERC20(...)` release funds using only an opaque `burnNullifier` without leaking `lezOwner`, `burnNonce`, or `lezSlot` on L1.
  - **Instance-Bound Explicit Unlock**:
    - `unlockETHWithInstance`, `unlockETHWithInstanceAndQuorum`, and ERC-20 counterparts verify burn receipts with EIP-712 domain separation and replay nullifiers (`executedBurns`).
  - Strictly prevents replay attacks using the `executedBurns` nullifier registry (`mapping(bytes32 => bool)`).
  - Releases locked ETH directly to `recipient`.

> [!NOTE]
> `MosooLocker` **v4** (including `depositShieldedETH`, `DepositCommitted`, `unlockShieldedETH`, `strictFixedDenominationMode`, payload-bound large withdrawal 24h queue, irreversible privacy flags post-commissioning, legacy retirement, and `2-of-2` production quorum via `commissionLocker`) is live on Ethereum Sepolia at [`0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd`](https://sepolia.etherscan.io/address/0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd) (block `12119389`). Historical v3 (`0x374B...`), v2 (`0xEFEf...`), and v1 (`0x7462...`) deployments are preserved in `contracts/deployments/sepolia.json`.

- **Trust Model & Security Guarantees**:
  - **Asymmetric Hybrid Trust Model**:
    - **Inbound (ETH -> LEZ)**: Consensus tracking and MPT receipt inclusion proof verification inside the zkVM guest on LEZ.
    - **Outbound (LEZ -> ETH)**: Multi-layered witness-attested committee settlement with defense-in-depth:
      1. Multi-signer committee quorum (`unlockETHWithQuorum`, `unlockERC20WithQuorum`) requiring $M$-of-$N$ threshold signatures from authorized committee members.
      2. EIP-712 structured data signing with strict domain separation and contract address binding.
      3. Replay nullifier registry (`executedBurns[burnId]`).
      4. Rolling 24-hour daily withdrawal limits (`dailyWithdrawalLimitETH`, `dailyWithdrawalLimitERC20`) bounding maximum outflow velocity.
      5. Mandatory 24-hour timelock queue for large withdrawals ($\ge 10$ ETH).
      6. Permanent Guardian & Owner cancellation veto (`cancelledBurns[burnId]`), strictly preventing re-queueing of vetoed withdrawals.
      7. Mandatory 24-hour timelock on updating `attesterAuthority` or modifying committee quorum.
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

The contract test suites are written in Solidity under [`test/MosooLocker.t.sol`](./test/MosooLocker.t.sol) (`27` tests) and [`test/MosooZkBurnVerifier.t.sol`](./test/MosooZkBurnVerifier.t.sol) (`4` tests) and configured via [`foundry.toml`](../foundry.toml).

```console
# Run Solidity unit and fuzz tests with Foundry
forge test -vvv
```

## Canonical Deployments

| Network | Contract | Address | Transaction Hash | Explorer |
| :--- | :--- | :--- | :--- | :--- |
| **Ethereum Sepolia (Active v4 — Commissioned 2-of-2)** | `MosooLocker` v4 | `0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd` | `0x2af69c9cc3c5eb68ade512f4f913e361f1b369d29cb8cf69657cb3e58b70959a` | [Sepolia Etherscan](https://sepolia.etherscan.io/address/0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd) |
| **Ethereum Sepolia (v3 Historical)** | `MosooLocker` v3 | `0x374B9F073A6aC1aF2c147392319499e35E8C7e82` | `0x2fd1d318d43a5a82f1bed7d94e95610eee1919c5676f0490407c4af1b57102a7` | [Sepolia Etherscan](https://sepolia.etherscan.io/address/0x374B9F073A6aC1aF2c147392319499e35E8C7e82) |
| **Ethereum Sepolia (v2 Historical)** | `MosooLocker` v2 | `0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b` | `0xa13c8e1df8018335fdcb957d1ba257ccf32264c4ffe1cea32b319f2ae627a999` | [Sepolia Etherscan](https://sepolia.etherscan.io/address/0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b) |
| **Ethereum Sepolia (v1 Historical)** | `MosooLocker` v1 | `0x74625D146B8d9413F3c3976B323d94A739be7856` | `0x1b492d89631c7fb398008285e777781d95f48c1a07c9d6ca2d6be5459941b28b` | [Sepolia Etherscan](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) |

