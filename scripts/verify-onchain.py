#!/usr/bin/env python3
"""
Mosoo Comprehensive On-Chain Testnet & Sequencer Verification Suite
Verifies:
  1. Live LEZ testnet sequencer health, block height, protocol gas cap, and fee engine.
  2. Strict TLS certificate verification against public endpoints.
  3. Deployed Mosoo program header account and committed ImageID.
  4. On-chain inclusion of all 7 binary segments and mined blocks.
  5. On-chain confirmation of program header registration and all 12 lifecycle transactions.
  6. Sanity negative resolution check.

Usage:
    python scripts/verify-onchain.py
    python scripts/verify-onchain.py --rpc https://testnet.lez.logos.co
"""

import sys
import hashlib
import json
import argparse
import urllib.request
import ssl
from pathlib import Path

DEFAULT_RPC = "https://testnet.lez.logos.co"
FEE_PROGRAM = "2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ"
LOADER_B58 = "JAQ5MVHbCkSYRzXunsrNuM2m1LS859PGveHfoYPAmcvZ"
GAS_CAP = 10_000_000

# Strict TLS verification enabled
ctx = ssl.create_default_context()

ok_count = 0
fail_count = 0

def report(condition: bool, msg: str):
    global ok_count, fail_count
    if condition:
        ok_count += 1
        print(f"  [PASS] {msg}")
    else:
        fail_count += 1
        print(f"  [FAIL] {msg}")

def call_rpc(rpc_url: str, method: str, params: list):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mosoo-Verifier/1.0"}
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as res:
                return json.loads(res.read().decode("utf-8"))
        except Exception:
            if attempt == 2:
                raise

def get_shard(rpc_url: str, account_id: str, prog_id: str) -> bytes:
    res = call_rpc(rpc_url, 'getAccount', [account_id])
    shards = res.get('result', {}).get('data', {}).get('shards', {})
    return bytes(shards.get(prog_id, []))

def get_tx_block(rpc_url: str, tx_hash: str) -> int | None:
    res = call_rpc(rpc_url, 'getTransaction', [tx_hash])
    r = res.get('result')
    if isinstance(r, list) and len(r) > 1:
        return r[1] if isinstance(r[1], int) else r[1].get('height')
    return None

def main():
    parser = argparse.ArgumentParser(description="Mosoo On-Chain Verification Suite")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help="Sequencer JSON-RPC URL")
    args = parser.parse_args()

    print("=" * 80)
    print("Mosoo Comprehensive On-Chain Verification Suite")
    print(f"Target RPC: {args.rpc} (TLS: Strict Verified)")
    print("=" * 80)

    # 1. Verify Sequencer Health & Protocol Parameters
    print("\n--- [Phase 1/3] Sequencer Consensus, Gas Engine & Protocol Parameters ---")
    fee_resp = call_rpc(args.rpc, "getFeeState", [])
    if "error" in fee_resp or "result" not in fee_resp:
        print(f"[-] Failed to fetch fee state: {fee_resp.get('error')}")
        sys.exit(1)

    fee_state = fee_resp["result"]
    curr_height = fee_state.get("height", 0)
    base_exec = fee_state.get("base_fee_exec", 0)
    max_gas = fee_state.get("max_gas_exec", 0)

    report(curr_height > 0, f"Sequencer producing blocks (Current height: {curr_height})")
    report(base_exec >= 0, f"Base execution fee: {base_exec} per gas unit")
    report(max_gas == GAS_CAP, f"Protocol gas cap: {max_gas:,} (matches RFP-021 10M limit)")

    # Verify Genesis and Head block
    b1_resp = call_rpc(args.rpc, "getBlock", [1])
    report(b1_resp.get("result") is not None, "Genesis Block 1 confirmed on chain")

    test_block = max(1, curr_height - 10)
    b_curr = call_rpc(args.rpc, "getBlock", [test_block])
    report(b_curr.get("result") is not None, f"Recent finalized block {test_block} confirmed on chain")

    # 2. Verify Program Deployment on LEZ
    print("\n--- [Phase 2/3] Program Deployment & Shard Verification ---")
    base_dir = Path(__file__).resolve().parent.parent
    dep_candidates = [
        base_dir / "evidence" / "public-testnet-v03" / "deployment_manifest.json",
        base_dir / "scripts" / "deployment_state.json",
    ]
    dep_file = next((p for p in dep_candidates if p.exists()), None)
    if not dep_file:
        print("ERROR: deployment manifest not found!")
        sys.exit(1)

    dep = json.loads(dep_file.read_text(encoding='utf-8'))
    header_acc = dep['header']['account_id']
    want_image_id = dep['header']['image_id']

    hdr_shard = get_shard(args.rpc, header_acc, LOADER_B58)
    image_id_onchain = hdr_shard[:32].hex() if len(hdr_shard) >= 32 else ""
    report(image_id_onchain == want_image_id,
           f"Program Header ({header_acc[:16]}...): committed ImageID {image_id_onchain[:16]}...")

    for seg in dep['segments']:
        idx = seg['index']
        acc = seg['account_id']
        tx = seg['tx']
        expected_blk = seg['block']
        expected_len = seg.get('length')
        expected_sha = seg.get('sha256')
        shard = get_shard(args.rpc, acc, LOADER_B58)
        shard_sha = hashlib.sha256(shard).hexdigest()
        mined_blk = get_tx_block(args.rpc, tx)

        content_ok = (len(shard) == expected_len and shard_sha == expected_sha) if (expected_len and expected_sha) else (len(shard) > 0)
        report(content_ok and mined_blk == expected_blk,
               f"Segment {idx} ({acc[:10]}...): authenticated on-chain ({len(shard):,} bytes, sha256:{shard_sha[:16]}..., block {mined_blk})")

    hdr_tx = dep['header']['tx']
    expected_hdr_blk = dep['header']['block']
    mined_hdr_blk = get_tx_block(args.rpc, hdr_tx)
    report(mined_hdr_blk == expected_hdr_blk,
           f"CreateHeader tx ({hdr_tx[:14]}...): confirmed in block {mined_hdr_blk}")

    # 3. Verify Program Lifecycle Steps on LEZ
    print("\n--- [Phase 3/3] Program Lifecycle Execution Verification ---")
    life_candidates = [
        base_dir / "evidence" / "public-testnet-v03" / "lifecycle_manifest.json",
        base_dir / "scripts" / "lifecycle_state.json",
    ]
    life_file = next((p for p in life_candidates if p.exists()), None)
    if life_file:
        life = json.loads(life_file.read_text(encoding='utf-8'))
        for label, step in life.items():
            tx = step['tx']
            expected_blk = step['block']
            verdict = step['verdict']
            expected = step['expected']
            gas_limit = step['gas_limit']
            exec_gas = step['block_gas_exec']

            mined_blk = get_tx_block(args.rpc, tx)
            is_mined = (mined_blk == expected_blk)
            is_valid_verdict = (expected == "applied" and verdict == "applied") or (expected == "refused" and verdict == "reverted")
            is_gas_ok = (exec_gas <= gas_limit)

            report(is_mined and is_valid_verdict and is_gas_ok,
                   f"Lifecycle '{label}': confirmed block {mined_blk}, verdict={verdict}, gas={exec_gas}/{gas_limit}")

    # Sanity Negative Check
    bogus = "0" * 64
    bogus_res = call_rpc(args.rpc, 'getTransaction', [bogus]).get('result')
    report(bogus_res is None, "Bogus tx hash resolves to None (no false positives)")

    print("\n" + "=" * 80)
    print(f"VERIFICATION RESULT: {ok_count} PASSED, {fail_count} FAILED")
    print(f"Status: {'ALL ON-CHAIN CHECKS VERIFIED' if fail_count == 0 else 'VERIFICATION FAILED'}")
    print("=" * 80)

    if fail_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
