# Mosoo Operations & Operational Security Guide

This document describes the operational procedures, trust models, checkpoint recovery mechanisms, and multi-network deployment standards for the Mosoo Ethereum Consensus Light Client on the Logos Execution Zone (LEZ).

---

## 1. Trusted Head Provisioning & Authority Model

### 1.1 Architecture & Separation of Concerns

Mosoo strictly separates network-wide anchor observations from per-instance tracking:
- **Network-Wide Anchor Heads (`TrustedBridgeConfig.trusted_heads`)**: Global, authority-provisioned consensus checkpoints representing verified historical Ethereum state roots. Set exclusively by the contract authority or governance multisig.
- **Per-Instance Trusted Heads (`TrustedBridgeConfig.instance_trusted_heads`)**: Localized consensus progress tracked for each individual light-client PDA instance (`MosooInstance`).
- **Effective Instance Head Resolution**:
  ```text
  effective_head = instance_trusted_heads[instance_pda]
      .or_else(|| trusted_heads[chain_id])
  ```
  This ensures that an advance in Instance A never mutates the global chain anchor or affects Instance B's weak-subjectivity baseline.

### 1.2 Authority Model
- **Config Authority**: The LEZ account or governance multisig that owns the `TrustedBridgeConfig` PDA.
- **Allowed Operations**:
  - `register_trusted_head(chain_id, slot)`: Updates the chain-wide anchor head.
  - `register_trusted_instance(chain_id, instance_pda)`: Whitelists a canonical instance PDA.
  - `register_trusted_locker(chain_id, locker_address)`: Whitelists an authentic Ethereum deposit locker.
  - `allow_token(chain_id, token_address)`: Whitelists an ERC-20 token for trustless cross-chain minting.
  - `pause() / unpause()`: Emergency circuit breaker.

---

## 2. Weak-Subjectivity Bounds & Operational Freshness

### 2.1 The 54,000-Slot Rule

Under Ethereum consensus:
- **Consensus Weak Subjectivity Window**: ~1,728,000 slots (~240 days).
- **Mosoo Operational Freshness Bound**: `CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS = 54,000` slots (~7.5 days at 12s/slot).

### 2.2 Freshness Invariants
1. **Bootstrap Freshness**: Any new instance initialized via `bootstrap_instance` must use a finalized checkpoint within 54,000 slots of the chain's trusted anchor head:
   $$\text{bootstrap\_slot} + 54,000 \ge \text{anchor\_head}$$
2. **Update Progression**: Updates cannot skip backward (`update.attested_header.slot <= instance.current_slot` is rejected).
3. **Anchor Upper Bound**: Callers cannot supply an unauthenticated inflated slot (`s > anchor_head + 54,000` is rejected fail-closed).

---

## 3. Stalled Instance Recovery Procedure

If an active light-client instance stalls (e.g., due to an extended network partition or sequencer downtime exceeding 54,000 slots), it can no longer be updated via standard sync-committee updates because its weak-subjectivity window has expired.

### 3.1 Retirement and Replacement (ADR-004)

Instances are **strictly immutable** and cannot be overwritten in place. To restore light-client operations:

```
+-------------------+        +--------------------+        +---------------------+
|  Stalled Instance | -----> | Governance Anchor  | -----> | Fresh Instance PDA  |
|   (Slot <= S_st)  |        | Rotation (Slot S_0)|        |   (Bootstrap S_0)   |
|   [DEPRECATED]    |        |  (2-step timelock) |        |      [ACTIVE]       |
+-------------------+        +--------------------+        +---------------------+
```

1. **Step 1: Fetch Fresh Ethereum Checkpoint**:
   Query a trusted Ethereum beacon node for the latest finalized checkpoint:
   ```bash
   curl -s "https://ethereum-beacon-api.example.com/eth/v1/beacon/states/finalized/finality_checkpoints" | jq .
   ```
2. **Step 2: Propose Anchor Update via Governance**:
   Propose advancing `TrustedBridgeConfig.trusted_heads[chain_id]` to the new finalized slot $S_0$.
3. **Step 3: Execute Timelock**:
   Wait for the 2-step governance timelock delay (`GOVERNANCE_TIMELOCK_DELAY = 2 days`) to elapse. Execute the anchor update.
4. **Step 4: Initialize New Instance**:
   Submit `bootstrap_instance` with the new checkpoint header and sync committee proof:
   ```bash
   mosoo-cli bootstrap --chain-id 11155111 --checkpoint-slot $S_0 --checkpoint-root $ROOT
   ```
5. **Step 5: Pin New Instance**:
   Governance executes `register_trusted_instance(chain_id, new_instance_pda)`, retiring the old instance PDA from consumer whitelists.

---

## 4. Checkpoint Rotation & 2-Step Timelock Governance

To eliminate single-key compromise risks, all administrative changes to `MosooLocker.sol` and `TrustedBridgeConfig` enforce a mandatory 2-step timelock:

| Parameter / Action | Delay | Enforced By |
| :--- | :--- | :--- |
| Attester Authority Rotation | 2 days (172,800s) | `MosooLocker.initiateAttesterUpdate` |
| Guardian Authority Rotation | 2 days (172,800s) | `MosooLocker.initiateGuardianUpdate` |
| Quorum Threshold Modification | 2 days (172,800s) | `MosooLocker.initiateQuorumUpdate` |
| Daily Rate Limit Adjustment | 2 days (172,800s) | `MosooLocker.initiateRateLimitUpdate` |
| Large Withdrawal (>= 10 ETH) | 1 day (86,400s) | `MosooLocker.queueWithdrawal` |

### 4.1 Attester Committee Rotation Workflow
1. Call `initiateAttesterUpdate(newAttesters, newCount)` from owner key.
2. Event `AttesterUpdateInitiated` is emitted with unlock timestamp.
3. During the 48-hour timelock window, the Guardian can inspect the transaction.
4. After 48 hours, call `executeAttesterUpdate()`.

---

## 5. Supported Networks & Chain IDs

Mosoo core strictly validates chain IDs via `mosoo_core::types::is_supported_chain_id()`:

| Network Name | Chain ID | Status | Consensus Fork Support |
| :--- | :---: | :---: | :---: |
| Ethereum Mainnet | `1` | Supported | Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas |
| Ethereum Sepolia Testnet | `11155111` | Supported (Canonical) | Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas |
| Ethereum Holesky Testnet | `17000` | Supported | Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas |
| Hoodi (Deprecated) | `560048` | **REJECTED** | Fails closed (`is_supported_chain_id` returns `false`) |

> [!WARNING]
> The Hoodi testnet (chain ID `560048`) is deprecated. All daemons and CLI tools must target Holesky (`17000`), Sepolia (`11155111`), or Mainnet (`1`).

---

## 6. Privacy Modes & Operational Usage

When generating state attestations via `AttestStateArgs`:

| Mode | Enum Variant | Salt Requirement | Emitted Journal | Suitable Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Public** | `PrivacyMode::Public` | Salt forbidden / unused | Unshielded statement | Public data feeds, transparency oracles |
| **Address Private** | `PrivacyMode::AddressPrivate` | `privacy_salt: Some([u8; 32])` mandatory | Blinded subject & nullifier, raw value clear | Cross-chain settlement (ERC-20 & ETH claims) |
| **Confidential** | `PrivacyMode::Confidential` | `privacy_salt: Some([u8; 32])` mandatory | Blinded subject & SHA-256 value commitment | Private identity & balance proofs, zk-compliance |

> [!CAUTION]
> If `privacy_mode` is set to `Confidential` or `AddressPrivate` but `privacy_salt` is `None`, the verifier immediately rejects the transaction at Step 0 with `MosooError::InvalidBootstrap`. It will never silently fall back to an unshielded statement.

---

## 7. Emergency Procedures: Pause, Veto, and Rollback

### 7.1 Guardian Independent Veto
The independent `Guardian` key can immediately cancel any queued withdrawal:
```solidity
// Called by Guardian within 24 hours of queued large withdrawal
mosooLocker.vetoWithdrawal(withdrawalId);
```
- Effect: Marks `isVetoed[withdrawalId] = true`.
- Funds remain locked safely in the contract.
- Timelock execution reverts with `WithdrawalVetoed()`.

### 7.2 Emergency Bridge Pause
- In `MosooLocker.sol`: Owner calls `pause()` to freeze all deposits and withdrawals immediately.
- On LEZ runtime: Config authority calls `pause_bridge()` to reject `handle_attest_state` and consumer claim dispatch.
- Re-enabling requires multisig approval and `unpause()`.
