# Mosoo Deployment Provenance & Architectural Lineage

This document establishes the exact provenance, binary verification, and architectural lineage of the **Mosoo Ethereum Consensus Light Client** deployed on the Logos Execution Zone (LEZ).

---

## 1. Executive Summary

| Artifact | Identifier / Value | Role / Provenance |
|---|---|---|
| **Public Testnet Program Header** | `DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf` | Deployed on `https://testnet.lez.logos.co` (Block 78002) |
| **Committed ImageID** | `ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928` | Logos Reference Light Client Guest Program deployed by Logos Core |
| **Segment Shards (0–6)** | 7 on-chain accounts (589,735 bytes total) | 100% byte-exact SHA-256 verified on-chain via strict TLS |
| **Mosoo Dedicated Guest Source** | `methods/guest/src/main.rs` | Independent Mosoo v0.4 guest program (pipelined BLS under 10M gas, shielded journals, PDA binding) |
| **Target Architecture** | `riscv32im-risc0-zkvm-elf` | RISC Zero zkVM target ELF |

---

## 2. Public Testnet Canonical Reference Binary

On the public LEZ testnet v0.3.1 (`https://testnet.lez.logos.co`), Logos Core deployed the canonical **Reference Light Client Program Header** with ImageID:
```
ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928
```

Both RFP-021 applicant teams (Mosoo and Sextant) deployed and verified their consumer contracts, instance PDA initializations, and state transitions against this official canonical Reference Program Header on `testnet.lez.logos.co`. 

### On-Chain Segment Content Hashes
The 7 compiled ELF segment shards deployed at `https://testnet.lez.logos.co` are cryptographically verified byte-for-byte by `scripts/verify-lez-deployment.py` and `scripts/verify-onchain.py`:

```
Segment 0 (9kMYfik9LL...): 98,341 bytes | SHA-256: da263f1a53c61d5fcc251c36a560facaf6b5ea4cffdf652afd6a61d8a7146828
Segment 1 (J8H8P7xDyE...): 98,341 bytes | SHA-256: a5296c62ee5b9d62bc1b0ec1a20f82390b42f0591e531dcd10c8ca30dc641c7e
Segment 2 (3MBvzDvv8r...): 98,341 bytes | SHA-256: e8133d1e4ca6b1f4ac4c6fc746d2015e827f72ad0a3f016756722e7b25e73a38
Segment 3 (AfiiSJb4fD...): 98,341 bytes | SHA-256: bc8dbc192526d20ec21a843c068a2f5894975e784e215ad7761f38d4b559d214
Segment 4 (GHB4ujSQqx...): 98,341 bytes | SHA-256: ffc11f70e124b1fe399f9d07ad264aa5e9da590ee5e633b402900b95b76e27ec
Segment 5 (AF688xRPz7...): 98,341 bytes | SHA-256: 385f8d2c428435383977e95cb96d4ba01f2e39eca5d59b13ad913d2588570e2e
Segment 6 (2MnfW4GBu8...): 29,689 bytes | SHA-256: 71ae5199642abb9d41cbdae384af7a1fd7979c093fcfac1c5da102fb76564f65
```

---

## 3. Mosoo Independent Architecture

While the testnet verification executed against the shared canonical light client program, Mosoo's codebase is **100% independently authored from first principles**:

1. **`mosoo-core`:** Independent SSZ encoding/decoding, generalized index calculations, BLS aggregate signature verification, Merkle-Patricia Trie (MPT) inclusion proofs, and privacy salt hashing. Zero shared code with Sextant.
2. **`methods/guest/`:** Dedicated Mosoo v0.4 guest program supporting:
   - 3-transaction split pipeline (`begin_update` -> `miller_update` -> `finish_update`) strictly under the 10M gas cap.
   - Address-private shielding preventing consumer recipient and amount leakage in zkVM journals.
   - Cross-instance PDA binding preventing cross-contract replay.
3. **`consumers/`:** Independent `ether-receiver` and `erc20-receiver` smart contracts enforcing double-claim prevention, nullifier PDA derivation, and balance ledgers.
4. **`contracts/`:** `MosooLocker.sol` V2 supporting EIP-712 domain separation, multi-signer quorum governance, and emergency guardian vetos.

---

## 4. Mosoo v0.4 Guest Deployment Pipeline

For the upcoming LEZ v0.4 devnet/testnet upgrade, Mosoo's dedicated guest binary can be deterministically compiled and deployed via:

```bash
# 1. Deterministic build via Docker
docker build -t mosoo-guest-builder -f docker/Dockerfile.guest .

# 2. Extract verified RISC-V ELF
docker run --rm mosoo-guest-builder

# 3. Deploy new program header to LEZ sequencer
python3 scripts/lez_deploy.py --elf target/riscv32im-risc0-zkvm-elf/release/mosoo-guest
```
