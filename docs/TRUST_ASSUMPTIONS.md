# Mosoo Cryptographic Trust Assumptions & Operational Security Model

Cryptographic trust assumptions, threat model, participant failure conditions, and privacy boundaries for the **Mosoo Ethereum Consensus & State Attestation Module** on the Logos Execution Zone (LEZ).

---

## 1. Consensus Checkpoint Trust & Weak Subjectivity

### 1.1 Genesis Checkpoint Provenance
- **Bootstrap Trust Anchor:** A Mosoo light client instance is initialized with a trusted consensus checkpoint (`trusted_slot`, `finalized_header_root`, and `current_sync_committee`).
- **Checkpoint Source:** Initializing operators acquire the trusted checkpoint from an authenticated Ethereum consensus node or canonical beacon state archive (e.g. Period 1884, slot 15,433,728).
- **Cryptographic Immutability:** Once initialized, the instance is immutable. The `genesis_validators_root` and `chain_id` are permanently anchored into the instance PDA. Checkpoint parameters cannot be rewritten or retroactively altered (ADR-004, `test_instance_immutability`).

### 1.2 Weak Subjectivity & Committee Rotation Bounds
- **Sync Committee Period vs Weak Subjectivity:**
  - **Sync Committee Rotation Period:** Every 256 epochs (8,192 slots, ~27.3 hours at 12s/slot). The light client must observe committee handoffs sequentially ($P_{sig} \le P_{store} + 1$) to authenticate rotated public keys.
  - **Ethereum PoS Weak Subjectivity:** A dynamic consensus parameter calculated under Ethereum specification based on active validator deposit balances and churn limits (dynamically calculated under the official Ethereum Consensus Specifications Weak Subjectivity Guide, typically ~14 to 28 days on Ethereum Mainnet). Light clients that remain offline longer than this window cannot trust historical validator signatures due to potential long-range slashing evasion.
  - **Mosoo Protocol Freshness Enforcement:** Mosoo enforces a two-tier defense:
    1. **Canonical Operational Window:** 54,000 slots (`CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS`, ~7.5 days at 12s/slot) for routine sync progression against trusted network anchors.
    2. **Hard Protocol Kill Switch (Dormancy Ceiling):** 1,728,000 slots (MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS / 54,000 epochs, ~240 days) acts as an absolute protocol kill switch. It is **not** a validity guarantee for ancient checkpoints (240 days is not a validity or freshness guarantee); actual Ethereum weak-subjectivity windows are dynamic (dynamically calculated chain-specific window per Ethereum Consensus Specifications, typically ~14–28 days on Ethereum Mainnet). Instead, 1.728M slots enforces hard fail-closed invalidation: dormant instances exceeding this boundary are permanently bricked and cannot be updated.\n- **Fail-Closed Protection:** Mosoo strictly rejects updates that skip sync committee periods (MosooError::SyncCommitteePeriodSkip) or fail weak-subjectivity freshness bounds (MosooError::WeakSubjectivityExpired). Any bootstrap or reinitialization must be anchored to an independently verified, currently acceptable checkpoint within the canonical weak-subjectivity window (~14–28 days). If an instance stalls past 1.728M slots, it cannot be rewritten in place; it must be retired and superseded by a fresh instance.\n
---

## 2. Cryptographic Quorum Trust: 2/3 Sync-Committee Assumption

### 2.1 The 2/3 Honest Majority Assumption
Mosoo implements the standard Ethereum Altair/Electra Sync Committee light client consensus model:
- **Sync Committee Size:** 512 randomly sampled validators rotating every 256 epochs (8,192 slots).
- **Quorum Threshold:** A light client update is cryptographically valid if and only if at least **2/3 of active sync committee members** sign the beacon block root:
  $$\text{Participation} \ge \lceil \frac{2 \times 512}{3} \rceil = 342 \text{ validators}$$
- **BLS12-381 Aggregate Signature:** Verified in-guest across the 3-transaction split pipeline (`BeginUpdate`, `MillerUpdate`, `FinishUpdate`) via optimized `blst` pairing arithmetic without relying on host-level precompiles.

### 2.2 Security vs Adversarial Collusion Bounds
- **$< 1/3$ Malicious Validators ($< 171$ nodes):** Zero impact. Updates continue smoothly and consensus advances without delay.
- **$\ge 1/3$ Colluding Validators ($\ge 171$ nodes):** Liveness stall risk. Malicious validators can refuse to sign, preventing the light client from reaching the 342-vote quorum. However, **safety is strictly preserved** — no false state or invalid headers can ever be finalized.
- **$\ge 2/3$ Colluding Validators ($\ge 342$ nodes):** Safety failure. If > 2/3 of Ethereum sync committee validators maliciously collude and sign an invalid block header, the light client would accept it. This is the fundamental, irreducible security assumption of all Ethereum light clients (identical to EIP-4788, Helios, and Telepathy).

### 2.3 Quorum Carryover Threat Model & Non-Automatic Exposure Bounds (VS.4)
- **Quorum Carryover Threat:** A malicious sync committee supermajority (>= 342 validators) could sign both a fraudulent finalized header and a fraudulent next sync committee root. Because future committees are authenticated via signed finalized headers, a compromised committee could attempt to chain fraudulent updates into subsequent periods unless halted.
- **Non-Automatic Exposure Boundary:** Committee rotation alone does NOT establish an automatic bound on the lifetime of a compromised trust chain. Exposure does not automatically terminate after 27.3 hours if the attacker successfully forges the next committee transition.
- **Defense-in-Depth & Mitigation Architecture:**
  1. **Consumer-Level Safeguards:** Consumer applications must independently bound financial exposure. `MosooLocker.sol` enforces rolling 24-hour withdrawal rate limits, a mandatory 2-day timelock for large transfers, and Guardian multisig veto power to freeze contract settlement upon abnormal activity.
  2. **Independent Checkpoint Verification & Fast Retirement (F.9, F.10):** The off-chain daemon cross-checks headers against independent Logos Ethereum Core RPC endpoints (`verify_checkpoint` API). If an off-canonical fork is detected, the compromised instance is immediately retired (F.10) and superseded by a fresh instance initialized from an independently verified canonical weak-subjectivity checkpoint.
  3. **Adversarial Invariant Test Suite:** Five specific adversarial regression tests validate invariant rejections under corrupt committee conditions (`tests/adversarial_mutation_tests.rs`):
     - Test 1: Rejection of updates with < 342 valid BLS signatures (`SubthresholdQuorumRejected`).
     - Test 2: Rejection of fabricated finalized headers against honest committee public keys.
     - Test 3: Detection and rejection of corrupt next-committee Merkle branch proofs.
     - Test 4: Chained update verification rejecting unanchored next-period transitions.
     - Test 5: Rejection of post-compromise recovery attempts without fresh independently verified weak-subjectivity checkpoints.

### 2.4 Quantitative Economic Attack Model (VS.4)

To rigorously evaluate the economic feasibility of corrupting a 512-member sync committee:

#### Staking Baseline (October 2026 Evaluation):
- **Active Staked Ethereum:** Approximately 44,112,742 ETH (~99.03 Billion USD total stake valuation at ~2,245 USD/ETH reference price).
- **Sampling Mechanism:** Every 256 epochs (~27.3 hours), 512 validator positions are sampled with effective-balance weighting from the active validator set.
- **Binomial Distribution Model:** Let $p$ denote the fraction of total active validator stake controlled by an attacker. The number of attacker-controlled seats $X$ in the sync committee is modeled by:
  $$X \sim \text{Binomial}(n = 512, p)$$

#### Supermajority Compromise Threshold:
To forge an accepted consensus update, the attacker must control at least $k = 342$ seats ($66.8\%$):
$$P(\text{Attack Success}) = P(X \ge 342) = \sum_{j=342}^{512} \binom{512}{j} p^j (1 - p)^{512 - j}$$

#### Exact Recalculated Attack Probability Distribution:

| Attacker Stake Fraction ($) | Illustrative Stake Valuation | Binomial Approx. (X \ge 342)$ (Per Period: ~27.3h) | Cumulative Annual Risk ( - (1 - P)^{321}$) | Feasibility & Security Interpretation |\n|---|---|---|---|---|\n| ** = 10\%$** | ~9.90 Billion USD | **.42 \times 10^{-210}$** | $\approx 4.56 \times 10^{-208}$ | Mathematically zero. Exceeds cryptographic security margins. |\n| ** = 33\%$** | ~32.68 Billion USD | **.19 \times 10^{-55}$** | $\approx 1.99 \times 10^{-52}$ | Infeasible. Corresponds to negligible cryptographic probability. |\n| ** = 50\%$** | ~49.52 Billion USD | **.18 \times 10^{-14}$** | $\approx 3.79 \times 10^{-12}$ | Negligible (~1 in 260 billion operating years). |\n| ** = 60\%$** | ~59.42 Billion USD | **.0888\%$ (.88 \times 10^{-4}$)** | **$\approx 24.8\%$** | Non-negligible over full operating year (~321 rotations). Demands consumer defense-in-depth! |\n| ** \ge 66.8\%$** | **~66.15 Billion USD** | ** \ge 0.50$** | ** \approx 1.00$** | Deterministic supermajority; stake-equivalent market valuation ~.15B. |\n
#### Reproducible Python Verification Script:
```python
import math

def binom_tail(n, k, p):
    return sum(math.comb(n, j) * (p**j) * ((1 - p)**(n - j)) for j in range(k, n + 1))

print("p=0.10:", f"{binom_tail(512, 342, 0.10):.2e}")  # 1.42e-210
print("p=0.33:", f"{binom_tail(512, 342, 0.33):.2e}")  # 6.19e-55
print("p=0.50:", f"{binom_tail(512, 342, 0.50):.2e}")  # 1.18e-14
print("p=0.60:", f"{binom_tail(512, 342, 0.60):.4%}")  # 0.0888%
```

#### Analytical Limitations & Mitigations:
1. **Simplified Sampling Model:** The binomial model treats sampling with replacement; actual Ethereum selection is effective-balance weighted without replacement, which further reduces variance and favors safety.
2. **Exogenous Correlated Staking Risk:** Liquid staking pools (e.g. Lido) or major infrastructure node operators could represent correlated failure domains. This risk is exogenous to the light client and is directly mitigated at the application layer via `MosooLocker.sol` rate limits, timelocks, and guardian vetoes.

---

## 3. Off-Chain Participants: Safety vs. Liveness Separation

Mosoo strictly decouples **Safety** (enforced mathematically in-guest under cryptographic hardness assumptions and zkVM proof soundness) from **Liveness** (which depends on off-chain operators):

| Participant | Role | Safety Impact | Liveness Impact | Trust Level Required |
| :--- | :--- | :---: | :---: | :--- |
| **Consensus Daemon (`mosoo-daemon`)** | Fetches headers, coordinates 3-Tx pipeline, submits transactions | **Negligible** (Cannot forge BLS aggregate signatures or falsify state) | Affects update latency (if all daemons crash, updates halt) | **Untrusted / Permissionless** |
| **zkVM Prover (Host Prover)** | Generates RISC0 SNARK execution receipts | **Negligible** (zkVM proof soundness guarantees invalid execution cannot produce a valid receipt) | Affects proof latency | **Untrusted / Permissionless** |
| **Logos Ethereum Core Proxy** | Verified consensus RPC gateway on Logos Core | **Negligible** (All payload roots are verified against authenticated beacon Merkle branches in-guest) | High-availability endpoint | **Semi-trusted transport; verified in-guest** |
| **Consuming dApp / Contract** | Mints tokens or settles transfers based on `VerifiedStatement` | **Negligible** (Only accepts verified nullifiers from authenticated instances) | Dependent on consumer logic | **Contract-governed** |

### 3.1 Permissionless Daemon Redundancy & Anti-Griefing
- Anyone can run `mosoo-daemon` without registration, staking, or API keys.
- **Randomized Jitter Delay (1.0x to 2.5x):** Prevents synchronized front-running when multiple independent daemons observe the same finalized beacon block.
- **Idempotency:** Re-submitting an already-finalized slot immediately exits cleanly without gas waste.

---

## 4. Privacy Boundaries & Cryptographic Shielding

### 4.1 On-Chain Privacy Guarantees
- **Zero Address Leakage:** Consumer smart contracts on LEZ store only the 32-byte deterministic nullifier (`statement_id`). Claimant Ethereum addresses, source transaction hashes, and signature bytes are never written to consumer state storage diffs.
- **Salted Blinding & Shielding:** Private state proofs support secret salting (`VerifiedStatement::shield_with_salt`), blinding the statement ID into `sha256("mosoo_salted_statement_id_v1:" || salt || statement_id)`.

### 4.2 Known Public Boundaries & Side-Channel Caveats
- **Public Source Chain Transparency:** Ethereum Mainnet and Sepolia are public blockchains. The original deposit transaction, sender address, and deposit amount are permanently visible on Ethereum block explorers.
- **Off-Chain Traffic Analysis Correlation:** If an Ethereum transaction deposits `7.4912 ETH` at 12:00 UTC and an account on LEZ claims `7.4912 mETH` at 12:02 UTC, external observers can correlate the two events off-chain via deposit amounts and timestamp proximity.
- **Production Unlinkability Path:** True cryptographic unlinkability in production requires relayer batching, standard deposit denominations (e.g., fixed 0.1, 1.0, 10.0 ETH tranches), or time-delayed batch claims.

---

## 5. Failure Conditions, Edge Cases & Recovery Modes

### 5.1 Incomplete 3-Transaction Split Pipeline
- **Scenario:** A daemon submits `BeginUpdate` (Tx 1) and `MillerUpdate` (Tx 2), but crashes before submitting `FinishUpdate` (Tx 3).
- **Handling:** Intermediate state is held in an authenticated PDA buffer (`MillerStateBuffer`). Any competing daemon can inspect the active job slot and submit `FinishUpdate` using the existing authenticated buffer. If uncompleted beyond 256 slots, the buffer expires and can be reset without deadlock.

### 5.2 Deep Chain Reorganizations
- **Finality Invariant:** Mosoo anchors strictly to **finalized** Ethereum beacon headers (Casper FFG 2-epoch finality). Reorganizations of finalized beacon headers require corrupting a 2/3 Casper FFG validator supermajority, resulting in the catastrophic slashing of at least 1/3 of total active staked Ethereum (> 33 Billion USD slashed under current baseline), bounded by economic consensus incentives rather than mathematical hash collision limits.
- **Unfinalized Blocks:** Mosoo strictly rejects optimistic, unfinalized execution heads.

### 5.3 Adversarial Rejection Matrix (Fail-Closed Guarantees)
- **Forged Beacon Root:** Fails BLS aggregate pairing verification in `MillerUpdate` / `FinishUpdate`.
- **Sub-Threshold Participation (< 342 validators):** Reverted with `MosooError::InsufficientParticipation`.
- **Tampered Merkle Proof:** Reverted with `MosooError::InvalidTrieProof`.
- **Duplicate Nullifier Submission:** Consuming contracts strictly revert with `AlreadyClaimed`.
- **Predicate Tampering (Attack 33):** Statement identity is derived from canonical underlying state facts (`derive_statement_id_v2`), ensuring altered predicates over the same event produce identical statement IDs and are strictly rejected.
