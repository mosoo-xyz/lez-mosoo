# Deployment Registry & On-Chain Verification

This document separates live deployed contracts/programs from local development and offline harness artifacts.

---

## 1. Environment Matrix

| Environment | Network / Endpoint | Status | On-Chain Assets | Scope Caveats |
|---|---|---|---|---|
| **1. Ethereum Sepolia (`MosooLocker` v4)** | EIP-155 `11155111` | Live EIP-170 hardened (`24,521 B`, `2-of-2` commissioned, shielded-only) | Contract `0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd` (block `12119389`, tx `0x2af69c9c...`), `productionCommissioned = true` `2-of-2` (`0x43358207...`), irreversible `shieldedDepositsOnly = true` (`0x1bad410e...`) & `strictFixedDenominationMode = true` (`0x9b9b1fcb...`), `permanentlyRetireLegacyRoutes` (`0xa955a123...`), payload-bound large ETH/ERC-20 withdrawal 24h queue (`10,000 USDC/USDT`), `DepositCommitted` (`0x29a9a209...` & `0x5beca8cd...`, `0.01 ETH`), `UnlockedShieldedETH` (`0x9a986ef0...`, `0.01 ETH`). Earlier v3 (`0x374B9F073A6aC1aF2c147392319499e35E8C7e82`), v2 (`0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b`), and v1 (`0x74625D146B8d9413F3c3976B323d94A739be7856`) retained in `contracts/deployments/sepolia.json`. | Outbound unlock relies on `2-of-2` EIP-712 attesters; 6-decimal ERC-20 tokens require pre-commission or 48h timelocked `proposeStandardDenomination` entries while `strictFixedDenominationMode == true`. |
| **2. LEZ Public Testnet v0.3.1 (`mosoo_lc`)** | `https://testnet.lez.logos.co` | Live deployed (`30/30` verified) | Program `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` (block `81148`, `immutable = true`, ImageID `961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0`, 6 ELF segments blocks `81142`–`81147`), 9 live txs (`81154`–`81163`). Live PDAs decode to Mainnet slot `15,632,352` / block `#26,392,691`. | Compiled prior to final workspace `mosoo-core` hardening (`is_supported_chain_or_configured`, Sepolia v2/v3/v4 `is_trusted_shielded_locker`, strict EIP-658 `status == [1u8]` & RLP/proof bounds); updated ELF verified in `V03State` local simulation while live redeployment awaits depleted public testnet faucet (`EfQhKQAk... = 0 LEZ`, `1,106,702` lepta remaining vs `~101M` needed); no standalone LEZ consumer token program deployed on-chain yet. |
| **3. LEZ v0.4 Target & Offline Harness** | Unreleased public `v0.4` / Local `LezRuntimeAdapter` | Upstream `v0.4` unreleased; offline tests pass | None upstream (public `v0.4` RPC/registry does not exist yet). | Compiled `artifacts/v04-guest/mosoo-guest` (`632,100` B, `9f724da2...`), signer-enforced `LezRuntimeAdapter`, `evidence/sequencer-harness-v04/run.tsv`, `335` Rust workspace tests, and `26` Foundry tests. |

---

## 2. Live Ethereum Sepolia Details (`contracts/deployments/sepolia.json`)

- **Active Hardened v4 Contract**: [`0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd`](https://sepolia.etherscan.io/address/0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd) (`CANONICAL_SEPOLIA_MOSOO_LOCKER_V4`, `24,521 B` runtime, EIP-170 compliant)
  - Deploy Tx: `0x2af69c9cc3c5eb68ade512f4f913e361f1b369d29cb8cf69657cb3e58b70959a` (Block `12119389`)
  - Deployer / Attester 1: `0xb1DF758aEff9E23b8049a807B188B9B67652B212`
  - Guardian (non-owner, enforced across rotations): `0x528605F78c650Cf4d84705e3dB85db37b4de30a0`
  - Hardening Txs: `setShieldedDepositsOnly(true)` (`0x1bad410e...`), `setStrictFixedDenominationMode(true)` (`0x9b9b1fcb...`), `permanentlyRetireLegacyRoutes()` (`0xa955a123...`), `commissionLocker(2-of-2)` (`0x43358207...`, setting `productionCommissioned = true` and locking privacy flags permanently)
  - `depositShieldedETH` (leaf `0`, `0.01 ETH`): `0x29a9a209e2beb5a18b0150a71e691e896b8306ef1b3002a14d6bdb6103e00e47` (Block `12119396`)
  - `unlockShieldedETH` (`2-of-2`, `0.01 ETH`): `0x9a986ef0e864a894e82b531ee710fab1c773ba71c265fc73db306d64f26404e8` (Block `12119398`)
  - Canonical `DepositCommitted` leaf (`leaf 1`, `0.01 ETH`): `0x5beca8cddc24ca97448b428b679642d88238df7b5502650a540817c2ccbc8c0c` (Block `12119399`)
- **Historical v3 Contract**: [`0x374B9F073A6aC1aF2c147392319499e35E8C7e82`](https://sepolia.etherscan.io/address/0x374B9F073A6aC1aF2c147392319499e35E8C7e82) (`CANONICAL_SEPOLIA_MOSOO_LOCKER_V3`, Block `12118809`).
- **Historical v2 Contract**: [`0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b`](https://sepolia.etherscan.io/address/0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b) (`CANONICAL_SEPOLIA_MOSOO_LOCKER_V2`, Block `12113191`, `DepositCommitted` vector in `vectors/sepolia/deposit_v2_shielded.json`).
- **Historical v1 Contract**: [`0x74625D146B8d9413F3c3976B323d94A739be7856`](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) (`CANONICAL_SEPOLIA_MOSOO_LOCKER`, Block `11989329`, `DepositETH` txs in blocks `11990019` and `12082214`).

---

## 3. Public LEZ v0.3.1 Parameters & Live Verification

| Parameter | Value | Method / Reference |
|---|---|---|
| Sequencer RPC | `https://testnet.lez.logos.co` | JSON-RPC 2.0 |
| Explorer | `https://explorer.testnet.lez.logos.co/` | Web explorer |
| Execution Gas Cap | `10,000,000` gas | `getFeeState.max_gas_exec` |
| Storage Gas Cap | `1,000,000` gas | `getFeeState.max_gas_stor` |
| Fee Program | `2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ` | `fee_core::fee_account_id()` |
| Program Loader | `JAQ5MVHbCkSYRzXunsrNuM2m1LS859PGveHfoYPAmcvZ` | `[0xFE; 32]` |
| Faucet Piñata Pool | `EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7` | Base58 account ID |
| Mosoo `mosoo_lc` | `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` | [`evidence/mosoo-testnet-v03/`](../evidence/mosoo-testnet-v03/README.md) |

```bash
# Verify Mosoo's live LEZ v0.3.1 deployment, 6 ELF segments, 9 txs & decoded Mainnet PDAs (30/30)
python3 scripts/verify-mosoo-lez.py

# Check faucet pool & wallet balance
python3 scripts/lez-wallet.py faucet-status
python3 scripts/lez-wallet.py new
python3 scripts/lez-wallet.py balance <account-id>

# Query live Sepolia v2 DepositCommitted + simulate LEZ bridge accounting locally
python3 scripts/testnet-two-way-bridge.py --mode live
```

*(Prior art note: [`docs/PRIOR_ART.md`](PRIOR_ART.md) discusses prior LEZ/Helios light-client designs including `edenbd1/lez-sextant` (`DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf`), which is kept strictly separate from Mosoo's `Co5EYuBR...` deployment.)*

---

## 4. Offline Harness Constants

Used locally by `mosoo-core`, `LezRuntimeAdapter`, `mosoo-cli`, and `evidence/sequencer-harness-v04/run.tsv`:
- `MOSOO_PROGRAM_ID`: `0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c`
- `CANONICAL_SEPOLIA_MOSOO_INSTANCE`: `0x984a6b2e81c318492c2c0abd211dfbbb641a3e71a5b27fcf806732ad55861912`
- `CANONICAL_MAINNET_MOSOO_INSTANCE`: `0xd8a26915e87ae4e96e786ddbfddb1d33402e03b915d9ef5ec5e2c1ac86977c42`
- `CANONICAL_HOLESKY_MOSOO_INSTANCE`: `0x0830d8ed8df6ce82bdc844aa2f54253b60d01a62e9a462dc498b9a5b1596ccd0`
