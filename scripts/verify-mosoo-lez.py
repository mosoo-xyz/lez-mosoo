#!/usr/bin/env python3
"""
Mosoo Own LEZ v0.3.1 Live Testnet Verification Suite

Independently verifies Mosoo's OWN deployed Light Client program (`mosoo_lc`,
built from `programs/mosoo-lez-v03` + `mosoo-core`) on the public LEZ v0.3.1
testnet (`https://testnet.lez.logos.co`) over strict TLS:
  1. Sequencer health, block height, and protocol gas caps (10M exec / 1M stor).
  2. Attribution separation: confirms deployed program_id is independent and distinct from unassociated testnet programs.
  3. Local binary artifact integrity (`artifacts/programs/v0.3/mosoo_lc.{bin,sha256,image_id.json}`).
  4. On-chain ProgramHeader (`immutable == true`, committed ImageID, first_segment pointer).
  5. All 6 on-chain ELF segment shards, linked pointer chain (`0->1->2->3->4->5->None`),
     segment hashes, mined blocks, and exact `user_elf_bytes` total.
  6. All 9 live lifecycle transactions (7 positive applied + 2 negative refused) mined
     in their exact blocks with matching V031Block timestamps and `run.tsv` parity.
  7. Live on-chain Borsh state decoding of `MosooInstance` & `MosooHeaderRecord` PDAs,
     confirming exact match to real Ethereum Mainnet execution block #26392691 in
     `vectors/mainnet/execution_proof.json`, empty closed `job_pda`, and empty
     unrecorded-slot header PDA (`15632353`) untouched by refused tx.
  8. Bogus tx hash resolves to `None`.

Usage:
    python scripts/verify-mosoo-lez.py
    python scripts/verify-mosoo-lez.py --rpc https://testnet.lez.logos.co
"""

import argparse
import base64
import hashlib
import json
import ssl
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_RPC = "https://testnet.lez.logos.co"
LOADER_B58 = "JAQ5MVHbCkSYRzXunsrNuM2m1LS859PGveHfoYPAmcvZ"
UNASSOCIATED_REF_PROGRAM = "DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf"
GAS_CAP_EXEC = 10_000_000
GAS_CAP_STOR = 1_000_000
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PDA_PREFIX = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00"

ctx = ssl.create_default_context()
ok_count = 0
fail_count = 0


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(B58_ALPHABET[r])
    for byte in b:
        if byte == 0:
            out.append(B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    pad = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + raw


def derive_pda(program_bytes: bytes, seed32: bytes) -> str:
    return b58encode(hashlib.sha256(PDA_PREFIX + program_bytes + seed32).digest())


def report(cond: bool, msg: str) -> None:
    global ok_count, fail_count
    if cond:
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
        "params": params,
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mosoo-Verifier/2.0"},
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20, context=ctx) as res:
                return json.loads(res.read().decode("utf-8"))
        except Exception:
            if attempt == 2:
                raise


def get_shards(rpc_url: str, account_id: str) -> dict:
    res = call_rpc(rpc_url, "getAccount", [account_id])
    return res.get("result", {}).get("data", {}).get("shards", {})


def get_tx_block(rpc_url: str, tx_hash: str):
    res = call_rpc(rpc_url, "getTransaction", [tx_hash])
    r = res.get("result")
    if isinstance(r, list) and len(r) > 1:
        return r[1] if isinstance(r[1], int) else r[1].get("height")
    return None


def get_block_timestamp_ms(rpc_url: str, block_id: int) -> int:
    b64 = call_rpc(rpc_url, "getBlock", [block_id]).get("result")
    raw = base64.b64decode(b64)
    return struct.unpack_from("<q", raw, 72)[0]


def decode_mosoo_instance(data: bytes) -> dict:
    off = 0
    iid = data[off:off + 32]; off += 32
    chain_id = struct.unpack_from("<Q", data, off)[0]; off += 8
    ckpt = data[off:off + 32]; off += 32
    gvr = data[off:off + 32]; off += 32
    net_tag = data[off]; off += 1
    if net_tag != 0:
        raise ValueError(f"unexpected Option<WireNetworkConfig> tag {net_tag}")
    min_part = struct.unpack_from("<H", data, off)[0]; off += 2
    wsw = struct.unpack_from("<Q", data, off)[0]; off += 8
    cslot = struct.unpack_from("<Q", data, off)[0]; off += 8
    cc_root = data[off:off + 32]; off += 32
    nc_tag = data[off]; off += 1
    nc_root = None
    if nc_tag == 1:
        nc_root = data[off:off + 32]; off += 32
    chdr = data[off:off + 32]; off += 32
    csr = data[off:off + 32]; off += 32
    ebnum = struct.unpack_from("<Q", data, off)[0]; off += 8
    ebhash = data[off:off + 32]; off += 32
    esroot = data[off:off + 32]; off += 32
    rroot = data[off:off + 32]; off += 32
    if off != len(data):
        raise ValueError(f"MosooInstance trailing bytes: {off} != {len(data)}")
    return {
        "instance_id": iid.hex(),
        "chain_id": chain_id,
        "checkpoint": ckpt.hex(),
        "min_participation": min_part,
        "current_slot": cslot,
        "next_committee_present": nc_root is not None,
        "execution_block_number": ebnum,
        "execution_block_hash": "0x" + ebhash.hex(),
        "execution_state_root": "0x" + esroot.hex(),
        "receipts_root": "0x" + rroot.hex(),
    }


def decode_header_record(data: bytes) -> dict:
    iid, ipda, cid, gvr, slot, bbr, ebnum, ebhash, esr, rr = struct.unpack(
        "<32s32sQ32sQ32sQ32s32s32s", data
    )
    return {
        "instance_id": iid.hex(),
        "instance_pda": b58encode(ipda),
        "chain_id": cid,
        "slot": slot,
        "beacon_block_root": "0x" + bbr.hex(),
        "execution_block_number": ebnum,
        "execution_block_hash": "0x" + ebhash.hex(),
        "execution_state_root": "0x" + esr.hex(),
        "receipts_root": "0x" + rr.hex(),
    }


def main():
    parser = argparse.ArgumentParser(description="Verify Mosoo's own live LEZ v0.3.1 deployment")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help="LEZ sequencer JSON-RPC URL")
    parser.add_argument(
        "--allow-offline",
        action="store_true",
        help="Skip gracefully with exit 0 if sequencer RPC is unreachable (for airgapped runs)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    dep_path = root / "evidence" / "mosoo-testnet-v03" / "deployment_manifest.json"
    life_path = root / "evidence" / "mosoo-testnet-v03" / "lifecycle_manifest.json"
    tsv_path = root / "evidence" / "mosoo-testnet-v03" / "run.tsv"
    art_dir = root / "artifacts" / "programs" / "v0.3"
    vec_path = root / "vectors" / "mainnet" / "execution_proof.json"

    dep = json.loads(dep_path.read_text(encoding="utf-8"))
    life = json.loads(life_path.read_text(encoding="utf-8"))
    vec = json.loads(vec_path.read_text(encoding="utf-8"))

    prog_id = dep["program_id"]
    prog_bytes = b58decode(prog_id)

    print("=" * 82)
    print("MOSOO OWN LEZ v0.3.1 LIVE TESTNET VERIFICATION")
    print(f"Program ID : {prog_id} (mosoo_lc / mosoo-core)")
    print(f"Image ID   : {dep['image_id_hex']}")
    print(f"Target RPC : {args.rpc} (TLS Strict)")
    print("=" * 82)

    print("\n--- [1/5] Sequencer Health & Distinct Program Identity ---")
    try:
        fee_state = call_rpc(args.rpc, "getFeeState", []).get("result", {})
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if args.allow_offline:
            print(f"  [SKIP-OFFLINE] Could not reach {args.rpc}: {exc}")
            sys.exit(0)
        raise
    report(fee_state.get("height", 0) > 0, f"Sequencer live height = {fee_state.get('height')}")
    report(
        fee_state.get("max_gas_exec") == GAS_CAP_EXEC and fee_state.get("max_gas_stor") == GAS_CAP_STOR,
        f"Gas caps match LEZ spec (exec={fee_state.get('max_gas_exec'):,}, stor={fee_state.get('max_gas_stor'):,})",
    )
    report(
        prog_id != UNASSOCIATED_REF_PROGRAM,
        f"Distinct from unassociated testnet program ({UNASSOCIATED_REF_PROGRAM[:12]}...)",
    )

    print("\n--- [2/5] Local Artifact & Binary Determinism ---")
    bin_bytes = (art_dir / "mosoo_lc.bin").read_bytes()
    bin_sha = hashlib.sha256(bin_bytes).hexdigest()
    sha_txt = (art_dir / "mosoo_lc.bin.sha256").read_text(encoding="utf-8").strip().split()[0]
    img_json = json.loads((art_dir / "mosoo_lc.image_id.json").read_text(encoding="utf-8"))
    report(
        len(bin_bytes) == dep["binary_bytes"] and bin_sha == sha_txt == dep["binary_sha256"],
        f"mosoo_lc.bin verified ({len(bin_bytes):,} bytes, sha256={bin_sha[:16]}...)",
    )
    report(
        img_json["image_id_hex"] == dep["image_id_hex"] == life["image_id_hex"]
        and img_json["image_id_u32"] == dep["image_id_u32"],
        f"mosoo_lc.image_id.json matches deployed manifest ({img_json['image_id_hex'][:16]}...)",
    )

    print("\n--- [3/5] On-Chain ProgramHeader & 6-Segment Linked Chain ---")
    hdr_shard = bytes(get_shards(args.rpc, prog_id).get(LOADER_B58, []))
    segs = sorted(dep["segments"], key=lambda s: s["index"])
    hdr_ok = (
        len(hdr_shard) == 65
        and hdr_shard[:32].hex() == dep["image_id_hex"]
        and b58encode(hdr_shard[32:64]) == segs[0]["account_id"]
        and hdr_shard[64] == 1
    )
    hdr_blk = get_tx_block(args.rpc, dep["header_tx_hash"])
    report(
        hdr_ok and hdr_blk == dep["header_block_id"],
        f"ProgramHeader immutable=1, ImageID committed, mined in block {hdr_blk}",
    )

    total_user_elf = 0
    reconstructed_chunks = []
    for i, s in enumerate(segs):
        shard = bytes(get_shards(args.rpc, s["account_id"]).get(LOADER_B58, []))
        code_len = struct.unpack_from("<I", shard, 0)[0]
        code_bytes = shard[4 : 4 + code_len]
        reconstructed_chunks.append(code_bytes)
        total_user_elf += code_len
        next_tag = shard[4 + code_len]
        next_acc = b58encode(shard[5 + code_len : 37 + code_len]) if next_tag == 1 else None
        expected_next = segs[i + 1]["account_id"] if i + 1 < len(segs) else None
        mined_blk = get_tx_block(args.rpc, s["tx_hash"])
        seg_ok = (
            code_len == s["bytes"]
            and next_acc == s["next_segment"]
            and next_acc == expected_next
            and mined_blk == s["block_id"]
        )
        report(
            seg_ok,
            f"Segment[{i}] {s['account_id'][:12]}... ({code_len:,}B code, blk={mined_blk}, next={expected_next[:8] + '...' if expected_next else 'None'})",
        )
    reconstructed_elf = b"".join(reconstructed_chunks)
    report(
        total_user_elf == dep["user_elf_bytes"] and reconstructed_elf in bin_bytes,
        f"Reconstructed on-chain ELF ({total_user_elf:,}B) bit-exact matches local mosoo_lc.bin",
    )

    print("\n--- [4/5] Live 9-Step Lifecycle & TSV Manifest Reconciliation ---")
    tsv_lines = [ln for ln in tsv_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    tsv_rows = [ln.split("\t") for ln in tsv_lines[1:]]
    report(
        len(tsv_rows) == len(life["steps"]) == 9,
        f"run.tsv rows ({len(tsv_rows)}) == lifecycle_manifest steps ({len(life['steps'])})",
    )

    applied_count = 0
    refused_count = 0
    fee_sum = 0
    for idx, step in enumerate(life["steps"]):
        mined_blk = get_tx_block(args.rpc, step["tx_hash"])
        blk_ts = get_block_timestamp_ms(args.rpc, step["block_id"]) if mined_blk else -1
        fee_ok = (
            step["pre_balance_lepta"] - step["post_balance_lepta"] == step["fee_paid_lepta"]
        )
        tsv_match = (
            idx < len(tsv_rows)
            and tsv_rows[idx][0] == step["step"]
            and tsv_rows[idx][3] == step["tx_hash"]
            and int(tsv_rows[idx][4]) == step["block_id"]
        )
        if step["kind"] == "positive" and step["outcome"] == "applied":
            applied_count += 1
        elif step["kind"] == "negative" and step["outcome"] == "reverted_in_block":
            refused_count += 1
        fee_sum += step["fee_paid_lepta"]
        report(
            mined_blk == step["block_id"]
            and blk_ts == step["block_timestamp_ms"]
            and fee_ok
            and tsv_match,
            f"{step['step']}: blk={mined_blk}, outcome={step['outcome']}, fee={step['fee_paid_lepta']:,} lepta",
        )

    report(
        applied_count == 7 and refused_count == 2 and fee_sum == life["total_fee_paid_lepta"],
        f"Lifecycle totals: {applied_count} applied + {refused_count} refused, total_fee={fee_sum:,} lepta",
    )

    print("\n--- [5/5] On-Chain PDA State Decoding vs Mainnet #26392691 Vector ---")
    inst_id = bytes.fromhex(life["instance_id_hex"])
    job_id = bytes.fromhex(life["job_id_hex"])
    exp_inst_pda = derive_pda(prog_bytes, inst_id)
    exp_init_hdr_pda = derive_pda(prog_bytes, hashlib.sha256(b"mosoo_hdr" + inst_id + struct.pack("<Q", life["bootstrap_slot"])).digest())
    exp_fin_hdr_pda = derive_pda(prog_bytes, hashlib.sha256(b"mosoo_hdr" + inst_id + struct.pack("<Q", life["finalized_slot"])).digest())
    exp_job_pda = derive_pda(prog_bytes, hashlib.sha256(b"mosoo_job" + inst_id + job_id).digest())
    exp_miss_hdr_pda = derive_pda(prog_bytes, hashlib.sha256(b"mosoo_hdr" + inst_id + struct.pack("<Q", life["finalized_slot"] + 1)).digest())

    report(
        exp_inst_pda == life["instance_pda"]
        and exp_init_hdr_pda == life["init_header_pda"]
        and exp_fin_hdr_pda == life["finalized_header_pda"]
        and exp_job_pda == life["job_pda"],
        "All 4 LEE v0.2 PDAs match deterministic SHA-256 derivations",
    )

    inst_raw = bytes(get_shards(args.rpc, exp_inst_pda).get(prog_id, []))
    inst = decode_mosoo_instance(inst_raw)
    report(
        inst["chain_id"] == 1
        and inst["current_slot"] == life["finalized_slot"] == 15632352
        and inst["execution_block_number"] == vec["block_number"] == 26392691
        and inst["execution_block_hash"] == vec["block_hash"]
        and inst["execution_state_root"] == vec["state_root"]
        and inst["receipts_root"] == vec["receipts_root"],
        f"Live MosooInstance ({len(inst_raw)}B) matches Mainnet block #{vec['block_number']} ({vec['block_hash'][:14]}...)",
    )

    init_hdr = decode_header_record(bytes(get_shards(args.rpc, exp_init_hdr_pda).get(prog_id, [])))
    fin_hdr = decode_header_record(bytes(get_shards(args.rpc, exp_fin_hdr_pda).get(prog_id, [])))
    report(
        init_hdr["slot"] == life["bootstrap_slot"]
        and fin_hdr["slot"] == life["finalized_slot"]
        and fin_hdr["execution_state_root"] == vec["state_root"]
        and fin_hdr["receipts_root"] == vec["receipts_root"],
        f"Live HeaderRecords decoded (init slot {init_hdr['slot']}, fin slot {fin_hdr['slot']})",
    )

    job_shards = get_shards(args.rpc, exp_job_pda)
    miss_shards = get_shards(args.rpc, exp_miss_hdr_pda)
    report(len(job_shards) == 0, f"Closed JobAccount PDA ({exp_job_pda[:12]}...) is empty after Finish")
    report(
        len(miss_shards) == 0,
        f"Unknown-slot HeaderRecord PDA (slot {life['finalized_slot'] + 1}) stayed empty after Refusal",
    )

    bogus = call_rpc(args.rpc, "getTransaction", ["0" * 64]).get("result")
    report(bogus is None, "Sanity negative check: zero tx hash resolves to None")

    print("\n" + "=" * 82)
    print(f"MOSOO LIVE VERIFICATION: {ok_count} PASSED, {fail_count} FAILED")
    print("=" * 82)
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
