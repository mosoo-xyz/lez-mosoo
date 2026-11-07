# Public LEZ v0.3.1 Testnet Execution Evidence

This directory contains live on-chain execution logs, sequencer consensus traces, and two-way bridge settlement evidence against the active **Logos Execution Zone (LEZ) Public Testnet** at `https://testnet.lez.logos.co` and **Ethereum Sepolia**.

---

## 1. Environment & Network Parameters

- **Public LEZ Testnet Sequencer:** `https://testnet.lez.logos.co`
- **LEZ Chain Block Height at Verification:** > 78,600
- **Protocol Execution Gas Cap:** `10,000,000` gas (`getFeeState.max_gas_exec`)
- **Protocol Base Execution Fee:** `8` gas units
- **Ethereum Network:** Sepolia Testnet (Chain ID: `11155111`)
- **Deployed Locker Vault:** [`0x74625D146B8d9413F3c3976B323d94A739be7856`](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) (Block 11989329)
- **Verified Vault Deposits:**
  - **Deposit 1:** [`0x743aea2f88e9c0d7fc8e3eeb55cddb1760d34e2714cd015afed2fac437945882`](https://sepolia.etherscan.io/tx/0x743aea2f88e9c0d7fc8e3eeb55cddb1760d34e2714cd015afed2fac437945882) (0.005 ETH, Block 11990019, Nonce 1)
  - **Deposit 2:** [`0x3ab00f69885de9df25408eeeb1dbe1df0c8a20558a5de11337e297cfc80eeef2`](https://sepolia.etherscan.io/tx/0x3ab00f69885de9df25408eeeb1dbe1df0c8a20558a5de11337e297cfc80eeef2) (0.010 ETH, Block 12012373, Nonce 2)
  - **Deposit 3:** [`0x6ecddbdd03284e4053a9fd957ebf611b188f9a67a2173a8b6b55844e0bcc8913`](https://sepolia.etherscan.io/tx/0x6ecddbdd03284e4053a9fd957ebf611b188f9a67a2173a8b6b55844e0bcc8913) (0.010 ETH, Block 12082214, Nonce 3)
- **Current Total Locked ETH in Vault:** `0.0250 ETH`

---

## 2. Evidence Files

1. **`sequencer_verification.txt`**:
   Live verification trace from `python3 scripts/verify-onchain.py` (27/27 checks passed under strict verified TLS), confirming live sequencer connectivity, block height progression, genesis block 1 integrity, recent finalized block verification, program header ImageID, all 7 segments on-chain, and all 12 lifecycle transaction steps.
2. **`live_bridge_execution.txt`**:
   End-to-end execution log from `python3 scripts/testnet-two-way-bridge.py --mode live`, proving:
   - Live on-chain deployment verification of `MosooLocker.sol` on Sepolia.
   - Live on-chain receipt & log decoding of `DepositETH` event.
   - 3-Tx light client update simulation on LEZ under 10M gas cap.
   - Deterministic `mETH` ledger state machine verification and peer-to-peer transfer on LEZ zkVM.
   - Invariant match: `Locked ETH == Active mETH`.
   - Replay-protected burn receipt generation and Ethereum unlock execution.
3. **`deployment_manifest.json` & `lifecycle_manifest.json`**:
   Full on-chain deployment and 12 lifecycle transaction manifests for independently verifying Mosoo's program deployment (`DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf`, ImageID `ad6fbedb983da6b6...`) via `python3 scripts/verify-lez-deployment.py` (29/29 checks passed).

---

## 3. Independent Reproduction

Anyone can independently reproduce these public testnet results with simple commands:

```bash
# 1. Verify deployed program, 7 segments, and 12 lifecycle transactions on public LEZ testnet (29 checks)
python3 scripts/verify-lez-deployment.py

# 2. Comprehensive master on-chain verifier: sequencer consensus, gas engine, program shards, and lifecycle (27 checks)
python3 scripts/verify-onchain.py

# 3. Run live cross-chain two-way bridge pipeline (Sepolia On-Chain Escrow + LEZ zkVM State Machine)
python3 scripts/testnet-two-way-bridge.py --mode live
```
