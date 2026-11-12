# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities in `mosoo-core`, `methods/guest`, `programs/mosoo-lez-v03`, `mosoo-daemon`, `mosoo-cli`, consumers, or `contracts/MosooLocker.sol` privately rather than opening a public GitHub issue:

- **Contact:** `contact@mosoo.xyz`
- **Include:** Affected commit SHA, component/file path, reproduction steps or PoC, and potential impact.
- **Response Target:** Acknowledgment within 48 hours and coordinated remediation prior to public disclosure.

Do **not** submit real-world private keys, mainnet funds, or live attack transactions against public endpoints when demonstrating an issue.

---

## Security Architecture & Known Boundaries

For protocol invariants, automated hardening suites, and current deployment boundaries, see:

- [`docs/security-review.md`](docs/security-review.md) — Core consensus/inclusion/escrow invariants and known audit boundaries.
- [`docs/TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md) — Sync-committee quorum model, weak-subjectivity windows, and economic attack bounds.
- [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) — Live Sepolia & LEZ v0.3.1 deployment scopes vs. unreleased LEZ `v0.4` offline targets.

### Emergency Circuit Breakers

- **`contracts/MosooLocker.sol`:** Independent `guardian` (`emergencyPause()`, `cancelQueuedWithdrawal()`, `cancelBurn()`, `cancelPendingGovernance()`) separated from `owner`, rolling 24h withdrawal caps, 24h queue on withdrawals `>= 10 ETH`, 48h multisig governance timelocks, irreversible `productionCommissioned` `>= 2` quorum latch, and `permanentlyRetireLegacyRoutes()`.
- **LEZ Light Client (`mosoo-core`):** Immutable initialized checkpoints (`No In-Place Overwrite`); compromised instances are superseded by deploying a fresh instance from an independently verified canonical Ethereum checkpoint.
