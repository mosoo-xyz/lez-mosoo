# Mosoo Own Live LEZ v0.3.1 Deployment & Execution Evidence (`mosoo_lc`)

This directory contains **first-party live deployment, local zkVM cycle simulation, and 9-transaction mainnet-backed lifecycle execution evidence** for **Mosoo's own** LEZ v0.3.1 program [`mosoo_lc`](../../programs/mosoo-lez-v03/src/lib.rs) (powered by `mosoo-core`) on the public LEZ v0.3.1 testnet (`https://testnet.lez.logos.co`).

> [!IMPORTANT]
> **Scope Separation:**
> - **This Directory (`evidence/mosoo-testnet-v03/`):** Records Mosoo's deployed `mosoo_lc` program `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` (`immutable = true`, ImageID `961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0`), compiled from `programs/mosoo-lez-v03/` + `mosoo-core/` and packaged into [`artifacts/programs/v0.3/mosoo_lc.bin`](../../artifacts/programs/v0.3/mosoo_lc.bin).
> - **LEZ v0.4 Target (`artifacts/v04-guest/mosoo-guest` & `evidence/sequencer-harness-v04/`):** Compiled `v0.4` ELF ready locally; public LEZ `v0.4` network deployment awaits upstream `v0.4` release.

---

## 1. Deployed Program & On-Chain Accounts (`https://testnet.lez.logos.co`)

| Entity | Account / Identifier | Block / Verification |
|---|---|---|
| **Program ID (`Header`)** | `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` | Block `81148` (`immutable = true`) |
| **Committed ImageID** | `961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0` | Matches [`mosoo_lc.image_id.json`](../../artifacts/programs/v0.3/mosoo_lc.image_id.json) |
| **Binary SHA-256 (`601,892` B)** | `0fc6ce723be2c507124f8e0fc6d0fab2b7c4454fdb4a1aa7b755667acb3e2bac` | [`mosoo_lc.bin`](../../artifacts/programs/v0.3/mosoo_lc.bin) (`569,468` B user ELF across 6 segments, blocks `81142`–`81147`) |
| **Mainnet Instance PDA** | `FZ1PjhneVpQSoFFaAjPEh2ygyA1DNQQsjoo5k6xJ3Gy9` | Decodes live to Mainnet slot `15,632,352` / execution block `#26,392,691` (`0x5f9597a4bbcc...`) |
| **Bootstrap Header PDA (`15632288`)** | `BoxmE7rx4xXHUKzGpmKK8vpbGW6t5RCbRoqTstmvQk1M` | `248` B `MosooHeaderRecord` |
| **Finalized Header PDA (`15632352`)** | `A6r38dnNmrdqJENbuprqZpWvPj2Khj4dysQJk9331oat` | `248` B `MosooHeaderRecord` (`state_root` + `receipts_root` verified) |
| **Split Pairing Job PDA** | `92x4rxU2z7uKvCX4RjWAkfNHgQJ4vLpWU4p2Xxo6KPkh` | Closed (`0` B shard after `Finish`) |

> [!NOTE]
> **Immutable Binary Provenance:** Deployed `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` and [`artifacts/programs/v0.3/mosoo_lc.bin`](../../artifacts/programs/v0.3/mosoo_lc.bin) (`ImageID 961a7e12...`) were compiled prior to the later workspace `mosoo-core` hardening patches (`crypto::is_supported_chain_or_configured` strict built-in chain validation and `TrustedBridgeConfig::is_trusted_shielded_locker` Sepolia v2 `0xEFEf...` default recognition). Because `Co5EYuBR...` is deployed `immutable = true`, it retains the pre-patch `TrustedBridgeConfig::canonical()` behavior unless redeployed to a new program account.

---

## 2. Live Mainnet-Backed Lifecycle & Measured zkVM Cycles (`<= 10M` Gas Cap)

Executed end-to-end on `https://testnet.lez.logos.co` (blocks `81154`–`81163`, total live fee `104,693,464` lepta; see [`lifecycle_manifest.json`](lifecycle_manifest.json) and [`run.tsv`](run.tsv)):

| Step | Kind | Outcome | Block | `r0vm 3.0.5` Cycles (`< 10M`) | Live Fee Paid (lepta) | Transaction Hash |
|---|---|---|---|---:|---:|---|
| `Init` | positive | `applied` | `81154` | `927,806` | `7,631,440` | `568c22ad1735fa9d09184efb529bb67b469b5308e4f4c3d32f5c7f653f42adca` |
| `Begin` | positive | `applied` | `81155` | `2,558,057` | `20,702,816` | `a98ffdfb8bc0d2297e7e575d4045782f611b81de8c0cd37d68de32701ab26b98` |
| `Miller` | positive | `applied` | `81156` | `4,568,088` | `36,547,544` | `f0da58e7aaeebe94eba4feee61e47548a518b5046f3a952f6fca98c2512d8777` |
| `Finish` | positive | `applied` | `81157` | `3,705,545` | `29,653,408` | `2dafa186af047a2f4753cfe6e838d25be3a095549a10204b193a84680d668ce9` |
| `Attest_WETH_Balance` | positive | `applied` | `81158` | `229,129` | `1,867,592` | `48f2147560d7c8dd1eaa22e7b1ae182332b18b9e79b05b603130146c7283073b` |
| `Attest_WETH_Storage` | positive | `applied` | `81159` | `362,755` | `2,960,912` | `4e05ec0ceb4b3dd385390c6177f7daa169fc5874d5b6ec80078298ccc3c7091e` |
| `Attest_USDC_Transfer_Confidential` | positive | `applied` | `81160` | `200,594` | `1,740,648` | `753bce1a48587889bb0474b45b0160bad7a6de50cdac71fdc24fed01799b1ce9` |
| `Refusal_Attest_Wrong_Chain` | negative | `reverted_in_block` | `81162` | — (`E7313`) | `1,794,552` | `9c0afdf9c168500ddcebd939dcb597256a273badeacc193cce4aba37d0062c45` |
| `Refusal_Attest_Unknown_Slot` | negative | `reverted_in_block` | `81163` | — (`E7392`) | `1,794,552` | `6bfd913c5fc561d04c9ee89e1dd9244f764a436b2a44a5ee0fc5ae74fdacd867` |

*(Note: `local_simulation.txt` additionally measures `Attest (Confidential Shielded)` at `212,812` cycles with explicit `PrivacyMode::Confidential` commitment output plus 7 adversarial refusals in local `lee::V03State`.)*

---

## 3. Independent Reproduction

```bash
# Full live 30/30 check (ProgramHeader, 6 segments + bit-exact local ELF match, 9 txs, PDA Borsh decoding vs Mainnet #26392691)
python3 scripts/verify-mosoo-lez.py
```

Latest saved verifier run: [`verify.txt`](verify.txt) (`30 PASSED, 0 FAILED`).
