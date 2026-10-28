# Mosoo Cryptographic Trust Assumptions & Operational Security Model

Cryptographic trust assumptions, threat model, participant failure conditions, and privacy boundaries for the **Mosoo Ethereum Consensus & State Attestation Module** on the Logos Execution Zone (LEZ).

---

## 1. Consensus Checkpoint Trust & Weak Subjectivity

### 1.1 Genesis Checkpoint Provenance
- **Bootstrap Trust Anchor:** A Mosoo light client instance is initialized with a trusted consensus checkpoint (`trusted_slot`, `finalized_header_root`, and `current_sync_committee`).
- **Checkpoint Source:** Initializing operators acquire the trusted checkpoint from an authenticated Ethereum consensus node or canonical beacon state archive (e.g. Period 1884, slot 15,433,728).
- **Cryptographic Immutability:** Once initialized, the instance is immutable. The `genesis_validators_root` and `chain_id` are permanently anchored into the instance PDA. Checkpoint parameters cannot be rewritten or retroactively altered (ADR-004, `test_instance_immutability`).

### 1.2 Weak Subjectivity Bounds
- **Epoch Horizon:** Under Ethereum's weak subjectivity specification (EIP-2982 / Altair), light clients must synchronize within the weak subjectivity period (~256 epochs / 27.3 hours).
- **Fail-Closed Protection:** Mosoo strictly rejects updates that skip sync committee periods or fail weak-subjectivity freshness checks (`MosooError::WeakSubjectivityViolation`). If a node goes offline for longer than a weak subjectivity period, it must bootstrap a new instance from an authenticated checkpoint rather than accepting unverified historical updates.

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

---

## 3. Off-Chain Participants: Safety vs. Liveness Separation

Mosoo strictly decouples **Safety** (which is guaranteed 100% cryptographically on-chain and in-guest) from **Liveness** (which depends on off-chain operators):

| Participant | Role | Safety Impact | Liveness Impact | Trust Level Required |
| :--- | :--- | :---: | :---: | :--- |
| **Consensus Daemon (`mosoo-daemon`)** | Fetches headers, coordinates 3-Tx pipeline, submits transactions | **ZERO** (Cannot forge BLS signatures or falsify state) | Affects update latency (if all daemons crash, updates halt) | **Untrusted / Permissionless** |
| **zkVM Prover (Host Prover)** | Generates RISC0 SNARK execution receipts | **ZERO** (zkVM soundness guarantees invalid execution cannot produce a valid receipt) | Affects proof latency | **Untrusted / Permissionless** |
| **Logos Ethereum Core Proxy** | Verified consensus RPC gateway on Logos Core | **ZERO** (All payload roots are checked against beacon Merkle trees in-guest) | High-availability endpoint | **Semi-trusted transport; verified in-guest** |
| **Consuming dApp / Contract** | Mints tokens or settles transfers based on `VerifiedStatement` | **ZERO** (Only accepts verified nullifiers from authenticated instances) | Dependent on consumer logic | **Contract-governed** |

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
- **Finality Invariant:** Mosoo anchors strictly to **finalized** Ethereum beacon headers (Casper FFG 2-epoch finality). Reorganizations of finalized beacon headers are cryptographically impossible without slashing at least 1/3 of the entire Ethereum validator set (> $30 Billion).
- **Unfinalized Blocks:** Mosoo strictly rejects optimistic, unfinalized execution heads.

### 5.3 Adversarial Rejection Matrix (Fail-Closed Guarantees)
- **Forged Beacon Root:** Fails BLS aggregate pairing verification in `MillerUpdate` / `FinishUpdate`.
- **Sub-Threshold Participation (< 342 validators):** Reverted with `MosooError::InsufficientParticipation`.
- **Tampered Merkle Proof:** Reverted with `MosooError::InvalidTrieProof`.
- **Duplicate Nullifier Submission:** Consuming contracts strictly revert with `AlreadyClaimed`.
- **Predicate Tampering (Attack 33):** Statement identity is derived from canonical underlying state facts (`derive_statement_id_v2`), ensuring altered predicates over the same event produce identical statement IDs and are strictly rejected.
