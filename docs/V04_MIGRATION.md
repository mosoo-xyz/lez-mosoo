# LEZ v0.3.1 → LEZ v0.4 Migration Guide & Cutover Status

This document explains how **Mosoo** bridges the current **LEZ v0.3.1** ecosystem and the upcoming **LEZ v0.4** specification, including exact binary, PDA, RPC, and deployment boundaries.

---

## 1. Current Upstream Network Status

| Environment | Upstream Status | Mosoo Status | Verification Mechanism |
|---|---|---|---|
| **LEZ Public Testnet v0.3.1 (Mosoo Own `mosoo_lc`)** | **Live** (`logos-execution-zone` v0.3.1) | **Live & Immutable at `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg`** (`mosoo-core` + `programs/mosoo-lez-v03/`, ImageID `961a7e12...`, blocks `81142`–`81163`). | `scripts/verify-mosoo-lez.py` (`30/30` live checks + Mainnet `#26,392,691` PDA decode) -> `evidence/mosoo-testnet-v03/`. |
| **LEZ Testnet v0.4** | **`v0.4.0-rc3` pre-release (`v0.3.2` latest stable); no public `v0.4` RPC live yet** | **`v0.4` ELF compiled (`artifacts/v04-guest/mosoo-guest`) + offline conformance ready** (`LezRuntimeAdapter` with signer binding, `MOSOO_PROGRAM_ID 0x01ab...`, SPEL PDAs, 10M gas cap budget). | `cargo test --workspace` (`340`) + `scripts/verify-evidence.py --manifest evidence/sequencer-harness-v04/run.tsv`. |
| **Ethereum Sepolia (Chain ID `11155111`)** | **Live** | **Live EIP-170 Hardened & Commissioned v4 `MosooLocker`** at `0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd` (`24,521 B` deployed v4 runtime, `productionCommissioned = true`, `2-of-2` quorum, irreversible `shieldedDepositsOnly = true` & `strictFixedDenominationMode = true`, payload-bound large ETH/ERC-20 withdrawal 24h queue, live `DepositCommitted` & `UnlockedShieldedETH` confirmed; earlier v3 `0x374B...`, v2 `0xEFEf...` & v1 `0x7462...` preserved). Updated contract source (`24,375 B`) adds `MosooZkBurnVerifier.sol` (`6,199 B`) + `unlockShieldedWithZkProof` (`31` Foundry tests). | Etherscan / Ethereum RPC (`scripts/testnet-two-way-bridge.py --mode live`, `vectors/sepolia/deposit_v2_shielded.json`). |

---

## 2. Protocol Changes Across v0.3.1 → v0.4 Target

### 2.1 Execution Model & Account Persistence
- **LEZ v0.3.1**: Programs run inside `program_loader` segments (`[0xFE; 32]`, 96 KiB chunks via `scripts/lez_deploy.py`) with `/LEE/v0.2/AccountId/PDA/` account derivation and public transaction envelopes (`/LEE/v0.3/Message/Public/`).
- **LEZ v0.4 Target**: Mosoo models `InstanceAccount`, `HeaderRecord`, and `JobAccount` mutations via `AccountStore` / `ProgramAccountStore` and `LezRuntimeAdapter<S>` in `mosoo-core/src/verifier.rs`. In production guest/runtime mode:
  - Caller-supplied unauthenticated stores are rejected fail-closed (`MosooError::UnauthenticatedInstance`).
  - `validate_initialize_with_config` and update/attestation entrypoints bind strictly to `TrustedBridgeConfig::load_strict(store)`.
  - Every `VerifiedStatement` embeds `genesis_validators_root`, `source_instance_id`, and `source_instance_pda` to prevent cross-instance replay (RFP-021 Functionality #15).

### 2.2 Single-Transaction Gas Cap (<= 10,000,000 Gas)
Both LEZ v0.3.1 (`getFeeState().max_gas_exec == 10_000_000`) and the LEZ v0.4 target enforce a strict 10M per-transaction gas cap. Mosoo splits BLS12-381 pairing verification into three resumable transactions (`BeginUpdate` -> `MillerUpdate` -> `FinishUpdate`) keyed by deterministic `JobAccount` digests.

### 2.3 Ethereum Consensus & State Extensions
- **Fork Coverage**: Mainnet (`1`), Sepolia (`11155111`, including Glamsterdam/Gloas slot `11,296,768` ePBS `block_hash` at gindex `2856` + RLP header root extraction), Holesky (`17000`), and Hoodi (`560048` Fulu at the consensus/CLI/daemon layer, or via `NetworkConfig` in custom initializers).
- **Shielded Privacy Modes**: `PrivacyMode::{Public, AddressPrivate, Confidential}` with salted commitments (`shield_with_salt`, `shield_confidential`) verified by consumers.

---

## 3. Cutover Checklist (When Public LEZ v0.4 Launches)

1. **Pin Upstream LEZ v0.4 SDK / Sequencer RPC**: Replace placeholder `v0.4` endpoints with the official Logos Core LEZ v0.4 RPC URL and `program_loader` binary wire spec once published.
2. **Reproducible Guest Build**: Compile `mosoo-guest` cleanly via Docker (`docker/Dockerfile.guest`, `rzup` RISC0 `rust` + `cpp` toolchains targeting `riscv32im-risc0-zkvm-elf`) and record its SHA-256 & ImageID.
3. **Update Deployer & Runtime Adapter**: Update `scripts/lez_deploy.py` (or native `logos-execution-zone` CLI) for v0.4 transaction envelope/loader changes, deploy `mosoo-guest` onto public LEZ v0.4 testnet, and archive a new `evidence/public-testnet-v04/` manifest.
4. **Update `MOSOO_PROGRAM_ID` / Registry & Switch `MosooLocker` v4 Instance Binding**: Register the live LEZ v0.4 program ID into Logos Core / SPEL catalog, point `mosoo-daemon` at the live v0.4 RPC, and configure production Mainnet `MosooLocker` (`0xF94eA0F9...` v4 is already deployed, EIP-170 compliant, hardened & commissioned `2-of-2` on Sepolia).
