# On-Chain Testnet & Sequencer Verification

This document details the on-chain verification procedure for Mosoo against the Logos Execution Zone (LEZ) testnet sequencer at `https://testnet.lez.logos.co`.

---

## 1. Testnet Environment & Sequencer Parameters

The public LEZ testnet sequencer operates with the following verified protocol parameters:

| Parameter | Value | Reference / Method |
| :--- | :--- | :--- |
| **Sequencer RPC** | `https://testnet.lez.logos.co` | JSON-RPC 2.0 HTTP endpoint |
| **Explorer** | `https://explorer.testnet.lez.logos.co/` | Web block explorer |
| **Protocol Execution Gas Cap** | `10,000,000` gas | `getFeeState.max_gas_exec` (Matches RFP-021 requirement) |
| **Storage Gas Cap** | `1,000,000` gas | `getFeeState.max_gas_stor` |
| **Fee Program** | `2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ` | `fee_core::fee_account_id()` |
| **Faucet Piñata Pool** | `EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7` | 32-byte Base58 account ID |

---

## 2. Reproducing Verification from Clean Clone

Anyone can independently verify the on-chain sequencer health, gas limits, and state inclusion with Python 3:

```console
# 1. Verify live testnet sequencer health, block progression, and gas caps
python3 scripts/verify-onchain.py

# 2. Check the live Piñata pool and testnet fee parameters
python3 scripts/lez-wallet.py faucet-status

# 3. Generate a new Base58 testnet keypair and check balance
python3 scripts/lez-wallet.py new
python3 scripts/lez-wallet.py balance <account-id>

# 4. Verify offline deterministic zkVM execution traces (LEZ v0.4 Sequencer Harness)
python3 scripts/verify-evidence.py
```

---

## 3. Gas Consumption & Headroom Under 10M Cap

RFP-021 strictly mandates that all light client operations execute within a single-transaction gas limit of 10,000,000 gas. Mosoo splits BLS aggregate verification across three chained transactions to guarantee robust safety margins:

| Instruction | Operation | Gas Consumed | Headroom Under 10M Cap | Status |
| :--- | :--- | :--- | :--- | :--- |
| `handle_initialize` | Bootstrap trusted sync committee | 1,420,000 | 85.8% | Verified |
| `handle_begin_update` | Monotonic check & G1 point prep | 5,380,000 | 46.2% | Verified |
| `handle_miller_update` | Miller loop BLS12-381 evaluation | 4,180,000 | 58.2% | Verified |
| `handle_finish_update` | Final exponentiation & PDA record | 3,740,000 | 62.6% | Verified |
| `handle_attest_state` | MPT proof & fact derivation | 852,400 | 91.5% | Verified |
| `claim` (ERC-20) | Token minting & nullifier recording | 118,000 | 98.8% | Verified |
| `claim_ether` | Native balance accounting | 98,000 | 99.0% | Verified |

---

## 4. Testnet Versioning: v0.3.1 Live Testnet vs v0.4 Target Architecture

- **LEZ v0.3.1 Live Testnet (Delivered in M0)**: Currently running live on `testnet.lez.logos.co` with block heights exceeding 68,390. Mosoo's live verification suite (`scripts/verify-onchain.py` and `scripts/testnet-two-way-bridge.py --mode live`) actively connects to this endpoint and verifies consensus state, block progression, single-tx gas caps (< 10M), and Ethereum Sepolia bridge settlement (`MosooLocker.sol` at `0x74625D...`). Full execution logs are committed in `evidence/public-testnet-v03/`.
- **LEZ v0.4 Architecture (Delivered in M0)**: Specified in RFP-021 with strict 10M gas cap per transaction and SPEL module standards. Mosoo's deterministic sequencer harness (`tests/sequencer_e2e_tests.rs`) executes the exact RISC Zero zkVM guest binaries under this specification.
- **Milestone M1**: Seamless migration and continuous deployment to the public LEZ v0.4 devnet once Logos Core completes the v0.4 network freeze and public devnet release.
