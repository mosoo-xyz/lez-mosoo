# Public LEZ v0.3.1 Testnet Execution Evidence

This directory contains live on-chain execution logs, sequencer consensus traces, and two-way bridge settlement evidence against the active **Logos Execution Zone (LEZ) Public Testnet** at `https://testnet.lez.logos.co` and **Ethereum Sepolia**.

---

## 1. Environment & Network Parameters

- **Public LEZ Testnet Sequencer:** `https://testnet.lez.logos.co`
- **LEZ Chain Block Height at Verification:** > 68,399
- **Protocol Execution Gas Cap:** `10,000,000` gas (`getFeeState.max_gas_exec`)
- **Protocol Base Execution Fee:** `8` gas units
- **Ethereum Network:** Sepolia Testnet (Chain ID: `11155111`)
- **Deployed Locker Vault:** [`0x74625D146B8d9413F3c3976B323d94A739be7856`](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) (Block 11989329)
- **Verified Vault Deposit:** [`0x743aea2f88e9c0d7fc8e3eeb55cddb1760d34e2714cd015afed2fac437945882`](https://sepolia.etherscan.io/tx/0x743aea2f88e9c0d7fc8e3eeb55cddb1760d34e2714cd015afed2fac437945882) (0.005 ETH, Block 11990019)

---

## 2. Evidence Files

1. **`sequencer_verification.txt`**:
   Live verification trace from `python3 scripts/verify-onchain.py`, confirming live sequencer connectivity, block height progression, genesis block 1 integrity, recent finalized block verification, and single-tx gas headroom (< 10M gas).
2. **`live_bridge_execution.txt`**:
   End-to-end execution log from `python3 scripts/testnet-two-way-bridge.py --mode live`, proving:
   - On-chain deployment verification of `MosooLocker.sol` on Sepolia.
   - On-chain receipt & log decoding of `DepositETH` event.
   - 3-Tx light client update simulation on LEZ under 10M gas cap.
   - 1:1 synthetic `mETH` minting and peer-to-peer transfer on LEZ.
   - Invariant match: `Locked ETH == Active mETH`.
   - Replay-protected burn receipt generation and Ethereum unlock execution.

---

## 3. Independent Reproduction

Anyone can independently reproduce these public testnet results with a single command:

```bash
# 1. Verify live LEZ testnet sequencer
python3 scripts/verify-onchain.py

# 2. Run live cross-chain two-way bridge pipeline
python3 scripts/testnet-two-way-bridge.py --mode live
```
