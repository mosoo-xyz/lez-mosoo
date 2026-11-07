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

Anyone can independently verify the on-chain sequencer health, gas limits, program deployment, and state inclusion with Python 3:

```console
# 1. Verify live LEZ testnet program deployment, 7 segments, and 12 on-chain lifecycle steps (29/29 checks)
python3 scripts/verify-lez-deployment.py

# 2. Comprehensive master on-chain verifier: sequencer, gas engine, program shard accounts, and lifecycle steps (27/27 checks)
python3 scripts/verify-onchain.py

# 3. Check the live Piñata pool and testnet fee parameters
python3 scripts/lez-wallet.py faucet-status

# 4. Generate a new Base58 testnet keypair and check balance
python3 scripts/lez-wallet.py new
python3 scripts/lez-wallet.py balance <account-id>

# 5. Verify live two-way bridge settlement: live Sepolia escrow deposit (tx 0x6ecddb...) + verified zkVM settlement state machine
python3 scripts/testnet-two-way-bridge.py --mode live

# 6. Verify offline deterministic zkVM execution traces (LEZ v0.4 Sequencer Harness)
python3 scripts/verify-evidence.py
```

---

## 3. Gas Consumption & Headroom Under 10M Cap

LEZ enforces a per-transaction gas limit of 10,000,000 gas. Mosoo splits BLS aggregate verification across three chained transactions to operate safely within this limit:

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

- **LEZ v0.3.1 Live Testnet (Delivered in M0)**: Currently running live on `testnet.lez.logos.co` with block heights exceeding 78,600. Mosoo's live verification suite (`scripts/verify-onchain.py` with 27/27 on-chain checks, `scripts/verify-lez-deployment.py` with 29/29 checks, and `scripts/testnet-two-way-bridge.py --mode live`) actively connects to the sequencer and verifies consensus state, block progression, single-tx gas caps (< 10M), and the two-way settlement pipeline (combining live Ethereum Sepolia escrow deposit at `0x74625D...` with verified zkVM state machine execution). Full execution logs and signed manifests are committed in `evidence/public-testnet-v03/`.
- **LEZ v0.4 Architecture (Delivered in M0)**: Specified in RFP-021 with strict 10M gas cap per transaction and SPEL module standards. Mosoo's deterministic sequencer harness (`tests/sequencer_e2e_tests.rs`) executes the exact RISC Zero zkVM guest binaries under this specification.
- **Public Devnet Target**: Deployment and continuous testing on the public LEZ v0.4 devnet once Logos Core completes the v0.4 network freeze and release.
