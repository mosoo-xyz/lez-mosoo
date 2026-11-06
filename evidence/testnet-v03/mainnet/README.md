# Mosoo Attester — Live LEZ Public Testnet Execution Evidence

This directory contains the **100% real, independently reproducible on-chain evidence** for the Mosoo RFP-021 deployment and full lifecycle execution on the public Logos Execution Zone testnet (`https://testnet.lez.logos.co`).

Unlike synthetic harness simulations, **every transaction listed below was broadcasted, processed, and sealed into public testnet blocks by the official LEZ sequencer**.

---

## 1. On-Chain Identity

| Parameter | Value |
|---|---|
| **Sequencer Endpoint** | `https://testnet.lez.logos.co` |
| **LEZ Protocol Version** | v0.3.1 |
| **Program Header Account (Program ID)** | `DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf` |
| **Committed Guest ImageID** | `ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928` |
| **Payer Account 1** | `3yJGpr3WjN3Tf9BpxdwdroAzgZDNBJtA8cCssGR4Rrmi` |
| **Payer Account 2 (Donor)** | `DWXnVbbBtcZfEZuqynDXU1xEzPwnkmArFP5m2QzkKhkU` |
| **Payer Account 3 (Donor 2)** | `6e978J6nNbfzjApzkKXJnVX2SHCw2Zvt4dZZJin1LCNf` |
| **Mosoo Instance PDA** | `S8EQuEjHgC9GQqNF1VJ3bB3K5EkZoF4qLubgNeNxiso` |
| **Checkpoint Header PDA** | `3wxFxxHvafsvuH8ZMX8CkTJfCma1FnVcSxq83aWeEY4x` |
| **Job Account PDA** | `D5UczYB6sPakbwXMjuY37caoRjWimTJiQCR9JAHUXoUh` |

---

## 2. On-Chain Program Deployment Trace

The Mosoo binary was split into 7 consecutive segments (Segment 0 to Segment 6) and registered via `CreateHeader`:

| Step | Block | Transaction Hash | Account ID / Shard |
|---|---|---|---|
| Segment 6 | **77987** | `0xa471e161e19ed904675f078c9fb8cf2cce1afe266ca323d12ede8c92ef76243b` | `2MnfW4GBu8YYUb4ZnujNfwcHJxhv47c6f8J8sEYaT7vC` |
| Segment 5 | **77993** | `0x310b720a1aa3d4cf9bd8814a7740a2d68e92b4d35c9e920dfb14ea7d5b748aac` | `AF688xRPz736yCutdgfcJdDPgsWw1dYwYZnZNhmEByak` |
| Segment 4 | **77994** | `0x76c6480d2a320183e6b0948eeb437fec5596994452f809b608f771a734bd6c78` | `GHB4ujSQqxEoq5A9TwyaAov6bvJcepowsZSNtikMHCrg` |
| Segment 3 | **77996** | `0xe7beafd20e290c7e0ea05758cd15d182c770d5c75d15ae1defb5e1a613da1016` | `AfiiSJb4fDAWMRtXGt6g1wCbp5F7TxNEuvDs3au7VDYD` |
| Segment 2 | **77997** | `0x16aa8a51e7e97d4c959df6dc389ad9a45c483075f30b6c1cfe45fb2ba3f0df4e` | `3MBvzDvv8rFiKhgTrp316XDbyY5L2ukWJ169i5n58kkA` |
| Segment 1 | **77999** | `0x1a704679aa8af788ae322109b142ab9ea174d6d362a6194093147c11bf35d0ca` | `J8H8P7xDyEo94SRCm7V1KcECADkWGqHRU3uhsBvZvYHJ` |
| Segment 0 | **78000** | `0x8577d170603f718d52e7c66712fd2146dd596ab9d32b8c9092637efe1705e310` | `9kMYfik9LLxw74QU61Tsmne2LZUb2iNNXBQQZ6uUVavK` |
| **CreateHeader** | **78002** | `0xce84756d4871a7a1d52cab0501f957c253246e4700476e63ace36f3ec4e50ca0` | `DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf` |

---

## 3. On-Chain Lifecycle Execution Trace (12 Steps)

| Step | Block | Transaction Hash | Gas Used | Verdict | Invariant Tested |
|---|---|---|---|---|---|
| `init` | **78005** | `0xa352523ad8b71309d5cde995dd68bc1448037d57c10840be2e0839d20bc549e9` | 2,017,028 | `applied` | Genesis instance initialization |
| `init-again` | **78006** | `0xca4ce883ea1956c3037edf19d1fe753a59bec72b7af53f7d6035ba0bb45f1b6d` | 2,017,028 | `reverted` | Re-initialization rejected (E7291) |
| `attest-log` | **78007** | `0x06786e483da40a3ff611d16faedccc9e677ba78885553d26becfd108a3e6fc1d` | 100,290 | `applied` | Valid event log inclusion verified |
| `attest-weth` | **78008** | `0xd069fe6c1b0e02e1d633c99d52a2c29abf13a230208cd878027129b59ec955ca` | 334,693 | `applied` | WETH balance storage proof verified |
| `attest-wrong-chain` | **78009** | `0x84ae77362a9e19660ecea529f7be5bb3d428946a0b8d10c5e419675cd3d3cf9f` | 100,290 | `reverted` | Cross-chain replay rejected (E7209) |
| `attest-predicate-false` | **78010** | `0xe5671b213e43bfb1013af78281415cff5be4a67bf424c94275a9d94afe798c94` | 100,290 | `reverted` | False predicate rejected (E7208) |
| `attest-slot-not-covered` | **78012** | `0x7a4e262a178a6bfd3816cd219d9f472aa435619c0d4dc1aa6ff2f4e5ee999290` | 334,693 | `reverted` | Invalid slot proof rejected (E7207) |
| `attest-unrecorded-header` | **78014** | `0xb4e4adef997942a306d7d75434d96c06f3f10877525e88585103e1f87e7ecd00` | 100,290 | `reverted` | Unrecorded slot rejected (E7292) |
| `u1-begin` | **78017** | `0x17cc899ac12ac8745a61a282704870ddcb417a5633ac10baf53795f7ede5f08a` | 5,600,000 | `applied` | Sync committee BLS aggregation begin |
| `u1-finish-before-miller` | **78022** | `0xb6b226e496a29c336f433dce8eaf5bb5499a31d0010febd04a1a014dd0022890` | 4,145,066 | `reverted` | Premature finish rejected (E7295) |
| `u1-miller` | **78023** | `0xdb6ac30bcd8eec14796a83bd2fa059d83e9b9266fd55911b7293de3f1bc66854` | 4,269,747 | `applied` | Two Miller loops pairing computed |
| `u1-finish` | **78025** | `0x8f9638f936c47fbacbd6c35c492234102c4bb52f63798ae60be3e36700fd6f6f` | 3,815,924 | `applied` | Final exponentiation verified & header committed |

---

## 4. How to Independently Verify

Run the automated verification script:
```bash
python scripts/verify-lez-deployment.py
```
Output:
```
======================================================================
  VERIFICATION RESULT: 22 PASSED, 0 FAILED
======================================================================
```

Or query any transaction directly via RPC curl:
```bash
curl -X POST https://testnet.lez.logos.co \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["8f9638f936c47fbacbd6c35c492234102c4bb52f63798ae60be3e36700fd6f6f"]}'
```
