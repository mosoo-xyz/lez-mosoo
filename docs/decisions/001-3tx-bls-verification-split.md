# ADR 001: 3-Transaction BLS Verification Split

## Status
Accepted

## Context
In the Logos Execution Zone (LEZ), smart contracts execute inside the RISC0 zkVM. LEZ enforces a per-transaction execution gas cap of approximately 10,000,000 gas (compute units / cycles).

Verifying an Ethereum Altair sync-committee aggregate signature requires:
1. Validating 512-bit participation (minimum 342 validators).
2. SSZ hash-tree-root and domain-separated signing root computation.
3. Multi-point aggregate public key computation from participating validators.
4. Point mapping: `hash_to_G2(signing_root)`.
5. Two Miller-loop pairings: `e(sig, G1) * e(msg, agg_pk)^-1`.
6. Final exponentiation in F_p12.

Even with the highly optimized, RISC0-accelerated `blst` crate, executing this complete pipeline in a single transaction requires approximately **13.4M to 14M gas**, exceeding the single-transaction cap.

## Decision
We split each light-client update into three discrete, sequential transactions linked via an on-chain `JobAccount` PDA:

```
[BeginUpdate]  -->  [MillerUpdate]  -->  [FinishUpdate]
(~5.4M gas)         (~4.2M gas)          (~3.8M gas)
```

1. **`begin_update`** (Tx 1):
   - Asserts monotonic slot progression and 2/3 participation threshold.
   - Aggregates participating validator public keys.
   - Computes `signing_root` and `hash_to_G2` curve point.
   - Writes intermediate inputs to `JobAccount` and advances stage to `JobStage::Miller`.

2. **`miller_update`** (Tx 2):
   - Reads `JobAccount` in `JobStage::Miller`.
   - Executes the two Miller-loop pairing computations.
   - Stores the raw $\mathbb{F}_{p^{12}}$ element in `JobAccount` and advances stage to `JobStage::Finish`.

3. **`finish_update`** (Tx 3):
   - Reads `JobAccount` in `JobStage::Finish`.
   - Computes the final exponentiation and verifies identity in $\mathbb{G}_T$.
   - Rejects the transaction if the signature is invalid.
   - Verifies the finality branch and sync-committee rotation branch.
   - Advances `instance.current_slot` and writes the verified `HeaderRecord`.
   - Closes or marks the job done.

## Consequences & Trade-offs

### Positive Consequences
- **Gas safety**: Every single transaction comfortably fits within the 10M gas cap (`begin` ~5.38M, `miller` ~4.18M, `finish` ~3.74M, providing 46% to 62% safety headroom).
- **Security equivalence**: Atomicity is preserved because state mutation (`current_slot` and `HeaderRecord`) occurs strictly in Tx 3 only after cryptographic pairing verification succeeds.
- **Permissionless execution**: Anyone can advance a pending job through its stages.

### Gas & Resource Trade-offs
- **Transaction Overhead:** Splitting verification across 3 transactions incurs three base transaction execution fees (~21,000 gas each) and two intermediate state writes to the temporary `JobAccount` PDA (~120,000 gas each). Total gas overhead is approximately ~350,000 gas higher than a theoretical single-transaction execution. Given the strict 10M per-tx limit on LEZ, this modest gas premium is an engineering necessity.
- **State Storage:** The `JobAccount` PDA holds intermediate group elements temporarily and is marked completed or reclaimed upon `finish_update`.

## Alternatives Considered & Rejected

1. **Host-Level BLS12-381 Precompiles:**
   - *Description:* Request or wait for Logos Core team to implement host-level precompiled contracts for BLS12-381 G1/G2 point addition and pairing.
   - *Why Rejected:* Mosoo is an application-level attestation module designed to deploy on current LEZ testnets immediately without requiring protocol hard forks, custom host runtimes, or privileged VM modifications.

2. **Unaccelerated Pure-Rust BLS (e.g. `arkworks` without assembly):**
   - *Description:* Execute pairing checks using pure-Rust algebraic crates.
   - *Why Rejected:* Profiling demonstrated that unaccelerated pairing routines consume > 28M cycles inside the zkVM, far exceeding even a 2-way split. Assembly-optimized `blst` was selected instead.

3. **Off-Chain SNARK/STARK Proof of Verification:**
   - *Description:* Prove the BLS signature verification inside an off-chain prover and submit only a succinct groth16/snark receipt to LEZ.
   - *Why Rejected:* Introducing an off-chain proving pipeline adds substantial prover latency (2–5 minutes per slot), high operational compute costs, and a centralized proving coordinator bottleneck. In contrast, in-guest verification via the 3-transaction split completes in under 30 seconds directly on-chain.

## Operational Assumptions & Failure Modes

- **Sequential Pipeline Completion:** A valid update requires all three transactions to execute in sequence (`Begin` -> `Miller` -> `Finish`). If an operator submits `begin_update` but crashes before completing `finish_update`, the job could temporarily block subsequent updates.
  - *Mitigation:* `JobAccount` includes a nonce and lease mechanism. Any independent operator can advance a stalled job by calling the next stage, or initiate a newer slot update once the slot lease window elapses.
- **Concurrent Submissions:** If multiple operators attempt to update the same slot simultaneously, their `begin_update` transactions compete.
  - *Mitigation:* `mosoo-daemon` incorporates randomized submission jitter ($1.0\times$ to $2.5\times$ poll interval) and idempotent transaction skipping (`AlreadyUpToDate`), preventing duplicate gas expenditure.
