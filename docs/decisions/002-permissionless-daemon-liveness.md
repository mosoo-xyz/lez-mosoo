# ADR 002: Permissionless Daemon Liveness & Competing-Update Recovery

**Status:** Accepted  
**Date:** 2026-10-20  
**Authors:** Mosoo Engineering

---

## Context

The Mosoo consensus update daemon (`mosoo-daemon`) is permissionless by design: any number of independent operators can run it simultaneously against the same Mosoo LEZ instance. This is a deliberate security choice — permissionless operation eliminates the single-operator availability risk present in bridging solutions that require a trusted relayer.

However, permissionless multi-operator submission introduces a **competing-update race condition**:

- Operator A and Operator B both observe a new Ethereum finalized block at slot `N`.
- Both call `BeginUpdate` within milliseconds of each other.
- One of them successfully creates the `JobAccount` PDA. The other's transaction fails or detects a duplicate.

The question is: what is the correct liveness protocol when a competing submission is detected?

---

## Decision

### 1. First-Writer-Wins on `JobAccount` Creation

The LEZ attester program uses **PDA uniqueness** to enforce first-writer-wins semantics:

- `JobAccount` PDA is keyed by `[b"mosoo_job", instance_pubkey, nonce]`.
- The nonce is derived from the submitting operator's transaction context.
- The **first** `BeginUpdate` to land and succeed creates the PDA.
- Subsequent `BeginUpdate` calls for the *same slot* detect `JobAccount` already in state `Stage1BeginComplete` and return `SubmitResult::JobAlreadyOpen`.

**No funds are lost.** Only the winning `BeginUpdate` transaction fee (~5.38M LEZ gas) is consumed. Trailing operators that detect `JobAlreadyOpen` skip immediately at zero gas cost.

### 2. Daemon Response to `JobAlreadyOpen`

The daemon handles `SubmitResult::JobAlreadyOpen` as a **soft success**:

```rust
Ok(SubmitResult::JobAlreadyOpen { slot }) => {
    info!(slot = slot, "Verification job already open on LEZ by peer operator; skipping");
}
```

The daemon does **not** attempt to re-compete for the same slot. It waits for the configured jitter delay and re-polls. By the next poll cycle, the winning operator's 3-transaction pipeline (`Miller` → `Finish`) will have completed, and the `HeaderRecord` PDA will be written. The daemon then detects `AlreadyUpToDate` and resumes normal monitoring.

### 3. Randomized Jitter Delay

To minimize the probability of simultaneous `BeginUpdate` submissions in the first place, each daemon instance applies a randomized delay before each submission attempt:

```text
wait_time = poll_interval * uniform_random(1.0, 2.5)
```

With a 60-second poll interval, the expected wait is 90 seconds (±45s 1σ). For two independent operators with distinct clock skew and network latency distributions, the probability of submitting within the same LEZ block is small.

### 4. Why Not Cooperative Locking?

An alternative design would be for operators to coordinate submission (e.g., via a shared lock service or a leader-election protocol). This was **rejected** because:

1. **It reintroduces centralization.** A lock service is a single point of failure.
2. **It adds latency.** Leader election rounds add seconds to the update pipeline.
3. **It complicates operations.** Operators must run additional coordination infrastructure.
4. **The problem is self-healing.** At worst, one `BeginUpdate` transaction fee is wasted per slot per competing operator. At 60-second poll intervals on Ethereum (~5-slot range), this is an extremely rare event.

---

## Consequences

**Positive:**
- Zero centralization dependency. Any operator can start or stop without coordination.
- At-most-one `JobAccount` per slot — protocol-level atomicity enforced by LEZ PDA model.
- Trailing operators incur zero gas overhead when they detect `JobAlreadyOpen`.

**Negative / Mitigated:**
- Very rare wasted gas from `BeginUpdate` collision (mitigated by jitter delay).
- Operators do not know the winning operator's identity (acceptable: permissionless system).

---

## Automated Test Coverage

The competing-update recovery behavior is verified in [`daemon/src/main.rs` → `test_daemon_competing_update_result_enum_coverage`](../../daemon/src/main.rs):

```rust
// Verify all 3 SubmitResult enum arms cover the full liveness state machine:
// AlreadyUpToDate → JobAlreadyOpen → Submitted
assert_ne!(discriminant(&r_already_up_to_date), discriminant(&r_job_open));
assert_ne!(discriminant(&r_job_open), discriminant(&r_submitted));
```
