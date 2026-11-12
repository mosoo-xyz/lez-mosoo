# Real Ethereum Chain Test Vectors

Committed cryptographic artifacts fetched from live Ethereum consensus (Beacon REST API) and execution (JSON-RPC) networks using [`scripts/fetch_real_vectors.py`](../scripts/fetch_real_vectors.py), verified by SHA-256 checksums in [`vectors/manifest.json`](./manifest.json).

These vectors anchor Mosoo's integration tests in [`mosoo-core/tests/real_chain_vectors_tests.rs`](../mosoo-core/tests/real_chain_vectors_tests.rs) and daemon parsing tests in [`daemon/src/main.rs`](../daemon/src/main.rs) against authentic production chain data rather than relying solely on synthetic test fixtures.

## Networks & Forks Covered

| Directory | Chain ID | Fork | Key Contents |
|---|---:|---|---|
| `vectors/mainnet/` | `1` | **Fulu** (`0x06000000`) | Real Mainnet bootstrap (`slot 15632288` & `15632352`), finality update (`fin 15632352` -> `att 15632429`, `sig 15632430`, EL block `26392691`), sync period updates (`1907` & `1908`), USDC + WETH `eth_getProof` account/storage MPT proofs (`execution_proof.json`), and live ERC-20 `Transfer` receipt proof (`receipt_proof.json`) |
| `vectors/sepolia/` | `11155111` | **Gloas ePBS** (`0x90000076`) | Real Sepolia Gloas bootstrap (`slot 11556544`, gindex `2945` depth 11), Gloas finality update (`execution_block_hash 0x5bf0dd87...` at gindex `2856`, `finality_branch` depth 9 at gindex `735`), period updates (`1409` & `1410`), full EL header RLP (`execution_block.json`, block `12112710`), live `MosooLocker` (`0x74625D146B8d9413F3c3976B323d94A739be7856`) MPT balance proof (`latest_proof_snapshot.json`, `0.025 ETH`), and live Sepolia `DepositETH` receipt proof (`deposit_12082214.json`, tx `0x6ecddbdd...`) |
| `vectors/hoodi/` | `560048` | **Fulu** (`0x70000910`) | Real Hoodi cross-period `530 -> 531` transition: period-`530` bootstrap (`slot 4349856`), `current_period_update.json` (signing `next_sync_committee` for period `531`), and `finality_update.json` (`fin 4349920` -> `sig 4349987` in period `531`) |

## Independent Verification

Run the committed real-chain test suites offline:

```bash
cargo test -p mosoo-core --test real_chain_vectors_tests
cargo test -p mosoo-daemon
```

Verify file integrity against [`manifest.json`](./manifest.json):

```bash
python3 -c '
import hashlib, json, pathlib
m = json.load(open("vectors/manifest.json"))
for net, info in m["networks"].items():
    for name, expected in info["hashes"].items():
        fname = "bootstrap.json" if name == "bootstrap_fin" else f"{name}.json"
        actual = hashlib.sha256(pathlib.Path("vectors", net, fname).read_bytes()).hexdigest()
        assert actual == expected, f"Mismatch in {net}/{fname}: {actual} != {expected}"
        print(f"OK  vectors/{net}/{fname} ({actual[:16]}...)")
'
```

## Refreshing Vectors

To capture fresh snapshots directly from public Ethereum Beacon and Execution RPCs (with local pure-Python Keccak/RLP/MPT pre-verification), run:

```bash
python3 scripts/fetch_real_vectors.py
```
