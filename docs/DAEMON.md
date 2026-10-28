# Mosoo Daemon — Operator Guide

`mosoo-daemon` is a permissionless, headless consensus update service. It continuously monitors an Ethereum beacon node for new finalized headers and submits the corresponding 3-transaction BLS verification pipeline to the Logos Execution Zone (LEZ) Mosoo instance.

> [!NOTE]
> **Permissionless Design:** Anyone may run this daemon simultaneously. Multiple operators running in parallel is safe and encouraged — the LEZ attester program is fully idempotent, and the daemon's randomized jitter delay (1× to 2.5× the configured poll interval) dramatically reduces the probability of duplicate submission gas waste.

---

## 1. Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Rust** | `1.78+` (`rustup default stable`) |
| **Ethereum Beacon Node** | Any Ethereum Beacon REST API-compatible node (Lodestar, Lighthouse, Prysm, Nimbus, Teku) |
| **Ethereum Execution Node** | Any EL JSON-RPC endpoint (Geth, Erigon, Nethermind, or provider such as Infura / Alchemy) |
| **LEZ Wallet** | A funded LEZ account for paying transaction gas (≈13.3M total LEZ gas / consensus update cycle) |
| **LEZ RPC** | Logos Execution Zone JSON-RPC endpoint (default local sequencer: `http://127.0.0.1:8545`) |

---

## 2. CLI Reference

```
mosoo-daemon [OPTIONS]
```

### Options

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--logos-ethereum-core-rpc <URL>` | `LOGOS_ETHEREUM_CORE_RPC` | `https://ethereum-core.logos.co` | **Canonical RFP-Compliant Endpoint:** Logos Ethereum Core verified consensus proxy |
| `--eth-consensus-rpc <URL>` | `ETH_CONSENSUS_RPC` | `https://lodestar-sepolia.chainsafe.io` | *Devnet Fallback:* Direct Beacon Node REST API (offline bootstrap only) |
| `--eth-execution-rpc <URL>` | `ETH_EXECUTION_RPC` | `https://gateway.tenderly.co/public/sepolia` | *Devnet Fallback:* Execution Layer JSON-RPC (offline bootstrap only) |
| `--eth-chain-id <ID>` | `ETH_CHAIN_ID` | `11155111` | EIP-155 chain ID (`1` = Mainnet, `11155111` = Sepolia, `560048` = Hoodi) |
| `--lez-rpc-url <URL>` | `LEZ_RPC_URL` | `https://testnet.lez.logos.co` | LEZ JSON-RPC sequencer URL |
| `--lez-private-key <HEX>` | `LEZ_PRIVATE_KEY` | — | Hex-encoded private key for gas payments |
| `--poll-interval-secs <N>` | `POLL_INTERVAL_SECS` | `60` | Base polling interval in seconds |
| `--log-format <FORMAT>` | `LOG_FORMAT` | `json` | Structured logs: `json` (production) or `pretty` |
| `--log-level <FILTER>` | `RUST_LOG` | `mosoo_daemon=info,warn` | `tracing`-compatible log filter string |

---

## 3. Running the Daemon

### 3.1 Sepolia Testnet (Recommended for Initial Testing)

```sh
export ETH_CONSENSUS_RPC="https://lodestar-sepolia.chainsafe.io"
export ETH_EXECUTION_RPC="https://rpc.sepolia.org"
export ETH_CHAIN_ID="11155111"
export LEZ_RPC_URL="http://127.0.0.1:8545"
export LEZ_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"

cargo run -p mosoo-daemon --release -- \
  --poll-interval-secs 60 \
  --log-format pretty
```

### 3.2 Ethereum Mainnet

```sh
export ETH_CONSENSUS_RPC="https://your-mainnet-beacon.example.com"
export ETH_EXECUTION_RPC="https://mainnet.infura.io/v3/YOUR_INFURA_KEY"
export ETH_CHAIN_ID="1"
export LEZ_RPC_URL="https://mainnet.lez.logos.co/rpc"
export LEZ_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"

cargo run -p mosoo-daemon --release -- \
  --poll-interval-secs 120 \
  --log-format json
```

### 3.1 Canonical RFP-Compliant Operation: Logos Ethereum Core Verified Proxy

In production, Ethereum consensus interactions route through the official **Logos Ethereum Core** verified consensus proxy module (--logos-ethereum-core-rpc). This provides consensus verification directly at the Logos node boundary without trusting third-party RPC providers:

```sh
# Production Configuration (Logos Ethereum Core Verified Proxy)
export LOGOS_ETHEREUM_CORE_RPC="https://ethereum-core.logos.co"
export ETH_CHAIN_ID="1"
export LEZ_RPC_URL="https://testnet.lez.logos.co"
export LEZ_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"

cargo run -p mosoo-daemon --release -- \
  --poll-interval-secs 60 \
  --log-format json
```

When `--logos-ethereum-core-rpc` is configured, consensus layer requests route through the authenticated module proxy:

```
{LOGOS_ETHEREUM_CORE_RPC}/v1/ethereum-core/consensus/{path}
```

### 3.2 Local Devnet Fallback: Direct Beacon Endpoint (Offline Bootstrap Only)

For isolated local testnets or offline development before the Logos Core catalog is mounted locally, operators can provide a fallback direct beacon endpoint:

```sh
# Local Devnet Fallback (Isolated developer environment only)
export ETH_CONSENSUS_RPC="https://lodestar-sepolia.chainsafe.io"
export ETH_EXECUTION_RPC="https://gateway.tenderly.co/public/sepolia"
export ETH_CHAIN_ID="11155111"
export LEZ_RPC_URL="https://testnet.lez.logos.co"
export LEZ_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"

cargo run -p mosoo-daemon --release -- \
  --poll-interval-secs 120 \
  --log-format json
```

---

## 4. Update Submission Lifecycle

Each polling cycle executes the following sequence:

```
Poll Cycle
│
├─ 1. Fetch current LEZ instance slot  (lez_getInstanceSlot RPC)
├─ 2. Fetch Ethereum finalized slot     (Beacon /eth/v1/beacon/headers/finalized)
│
├─ [If ETH slot <= LEZ slot] → Skip (already up to date)
├─ [If existing job open]    → Skip (peer operator already submitted)
│
├─ 3. Fetch LightClientFinalityUpdate  (Beacon /eth/v1/beacon/light_client/finality_update)
│
├─ 4. Submit Tx 1/3: BeginUpdate       (~5.38M LEZ gas)
│     Wait 500ms
├─ 5. Submit Tx 2/3: MillerUpdate      (~4.18M LEZ gas)
│     Wait 500ms
└─ 6. Submit Tx 3/3: FinishUpdate      (~3.74M LEZ gas)
      → HeaderRecord PDA written on LEZ
```

**Jitter delay:** After each complete cycle (success or transient failure), the daemon waits `(1.0× to 2.5×) × poll_interval_secs` before the next attempt, distributing submission load across independent operator instances.

---

## 5. Gas Cost Estimates

| Transaction | LEZ Gas Used | Headroom (< 10M Cap) |
| :--- | :---: | :---: |
| `begin_update` | ~5,382,140 | **46.2%** |
| `miller_update` | ~4,180,000 | **58.2%** |
| `finish_update` | ~3,740,000 | **62.6%** |
| **Full Consensus Cycle** | **~13,302,140** | All txs within cap |

For detailed cycle-level analysis, see [`docs/BENCHMARKS.md`](BENCHMARKS.md).

---

## 6. Structured Log Output

The daemon emits structured JSON logs (via `tracing-subscriber`). Example:

```json
{"timestamp":"2026-10-21T10:00:00Z","level":"INFO","target":"mosoo_daemon","chain_id":11155111,"consensus_rpc":"https://lodestar-sepolia.chainsafe.io","lez_rpc":"http://127.0.0.1:8545","poll_secs":60,"message":"Mosoo consensus update daemon started"}
{"timestamp":"2026-10-21T10:01:01Z","level":"INFO","target":"mosoo_daemon","current_lez_slot":15433728,"target_eth_slot":15433760,"message":"Fetching Beacon light client finality update"}
{"timestamp":"2026-10-21T10:01:02Z","level":"INFO","target":"mosoo_daemon","slot":15433760,"message":"Submitting Tx 1/3: BeginUpdate"}
{"timestamp":"2026-10-21T10:01:03Z","level":"INFO","target":"mosoo_daemon","job_nonce":42817,"message":"Submitting Tx 2/3: MillerUpdate"}
{"timestamp":"2026-10-21T10:01:04Z","level":"INFO","target":"mosoo_daemon","job_nonce":42817,"message":"Submitting Tx 3/3: FinishUpdate"}
{"timestamp":"2026-10-21T10:01:04Z","level":"INFO","target":"mosoo_daemon","slot":15433760,"message":"Successfully finalized consensus update on LEZ"}
{"timestamp":"2026-10-21T10:01:04Z","level":"INFO","target":"mosoo_daemon","wait_secs":89,"message":"Sleeping until next poll interval"}
```

Use `--log-format pretty` for human-readable terminal output during development.

---

## 7. Logos Core Module Catalog Integration Path

The `mosoo-daemon` is designed to integrate into the **Logos Core module catalog** as a registered Logos module, enabling:

1. **Managed Lifecycle:** Logos Core starts/stops/monitors the daemon as part of the LEZ node process.
2. **Verified Ethereum Proxy:** The `--logos-ethereum-core-rpc` flag connects to the Logos Ethereum Core module's verified consensus proxy, eliminating external beacon node dependencies for operators who run a full Logos Core node.
3. **SPEL IDL Registration:** Mosoo's `docs/SPEL_IDL.md` canonical interface definitions map directly to Logos Core module catalog schemas.

**Catalog registration path:** Logos Core Module Catalog & SPEL Integration.

---

## 8. Competing-Update Recovery

If two daemon operators submit `BeginUpdate` simultaneously (race condition), the LEZ attester program handles this safely:

- The first `BeginUpdate` to land creates the `JobAccount` PDA (`status: Stage1BeginComplete`).
- Subsequent `BeginUpdate` attempts for the same slot detect the already-open `JobAccount` and return `JobAlreadyOpen`.
- The daemon logs `"Verification job already open on LEZ by peer operator; skipping"` and waits for the next cycle.
- The winning operator's 3-transaction pipeline proceeds uninterrupted.

**No funds are lost.** Only the winning `BeginUpdate` transaction fee is consumed; trailing operators' skipped submissions cost zero gas.

---

## 9. Security Considerations

| Concern | Mitigation |
| :--- | :--- |
| **Private key exposure** | Use `LEZ_PRIVATE_KEY` env var, not `--lez-private-key` flag (avoids shell history) |
| **RPC endpoint trust** | Beacon API responses are cryptographically verified in-guest — daemon cannot forge updates |
| **Competing submissions** | Idempotent LEZ program + jitter delay prevents duplicate gas waste |
| **Long-range reorganizations** | Weak-subjectivity window enforced (1,728,000 slots) — stale instances require re-init |
| **Key management** | For production: use Logos Core wallet keystore rather than raw hex key flag |
