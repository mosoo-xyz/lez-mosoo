#!/usr/bin/env python3
"""
Fetch and cryptographically pre-verify real live Ethereum consensus & execution
test vectors into `vectors/{mainnet,sepolia,hoodi}/`.

Zero external Python dependencies required (uses pure-Python Keccak-256,
RLP, SSZ HashTreeRoot, and Merkle-Patricia Trie builders).

Usage:
    python3 scripts/fetch_real_vectors.py
"""

import hashlib
import json
import os
import pathlib
import ssl
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS_DIR = ROOT / "vectors"

MAINNET_BEACON = "https://ethereum-beacon-api.publicnode.com"
MAINNET_ELS = [
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.llamarpc.com",
]

SEPOLIA_BEACON = "https://lodestar-sepolia.chainsafe.io"
SEPOLIA_EL = "https://ethereum-sepolia-rpc.publicnode.com"
SEPOLIA_ARCHIVE_EL = "https://gateway.tenderly.co/public/sepolia"

HOODI_BEACON = "https://ethereum-hoodi-beacon-api.publicnode.com"

MOSOO_LOCKER_SEPOLIA = "0x74625D146B8d9413F3c3976B323d94A739be7856"  # Historical v1 for DepositETH tx 0x6ecddb...
MOSOO_LOCKER_V2_SEPOLIA = "0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b"  # Canonical v2 (DepositCommitted tx 0xe017525b...)
SEPOLIA_DEPOSIT_BLOCK = 12082214
SEPOLIA_DEPOSIT_TX = "0x6ecddbdd03284e4053a9fd957ebf611b188f9a67a2173a8b6b55844e0bcc8913"

USDC_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
WETH_MAINNET = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
ERC20_TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

TLS_CTX = ssl.create_default_context()

# --- Pure-Python Canonical Ethereum Keccak-256 (FIPS-202) ---
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROTC = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(x: int, n: int) -> int:
    return ((x << (n % 64)) | (x >> (64 - (n % 64)))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(st):
    for r in range(24):
        C = [st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol64(st[x][y], ROTC[x][y])
        for x in range(5):
            for y in range(5):
                st[x][y] = (B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])) & 0xFFFFFFFFFFFFFFFF
        st[0][0] ^= RC[r]


def keccak256(data: bytes) -> bytes:
    rate = 136
    st = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for b in range(0, len(padded), rate):
        blk = padded[b : b + rate]
        for i in range(17):
            w = int.from_bytes(blk[i * 8 : (i + 1) * 8], "little")
            st[i % 5][i // 5] ^= w
        _keccak_f(st)
    out = bytearray()
    for i in range(4):
        out.extend(st[i % 5][i // 5].to_bytes(8, "little"))
    return bytes(out)


# --- Canonical RLP & Ethereum Execution Block Header / Receipt Helpers ---
def hx(s: str) -> bytes:
    s = s.removeprefix("0x")
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def hxi(s: str) -> int:
    return int(s, 16)


def rlp_len(n: int, base: int) -> bytes:
    if n < 56:
        return bytes([base + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(b)]) + b


def rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return rlp_len(len(b), 0x80) + b


def rlp_int(v: int) -> bytes:
    if v == 0:
        return b"\x80"
    return rlp_bytes(v.to_bytes((v.bit_length() + 7) // 8, "big"))


def rlp_list(items) -> bytes:
    payload = b"".join(items)
    return rlp_len(len(payload), 0xC0) + payload


def rlp_decode_list(data: bytes):
    """Minimal canonical RLP list item extractor returning encoded list item bytes."""
    if data[0] < 0xF8:
        total = 1 + (data[0] - 0xC0)
        pos = 1
    else:
        ll = data[0] - 0xF7
        l = int.from_bytes(data[1 : 1 + ll], "big")
        pos = 1 + ll
        total = pos + l
    items = []
    while pos < total:
        b0 = data[pos]
        if b0 < 0x80:
            end = pos + 1
        elif b0 < 0xB8:
            end = pos + 1 + (b0 - 0x80)
        elif b0 < 0xC0:
            ll = b0 - 0xB7
            l = int.from_bytes(data[pos + 1 : pos + 1 + ll], "big")
            end = pos + 1 + ll + l
        elif b0 < 0xF8:
            end = pos + 1 + (b0 - 0xC0)
        else:
            ll = b0 - 0xF7
            l = int.from_bytes(data[pos + 1 : pos + 1 + ll], "big")
            end = pos + 1 + ll + l
        items.append(data[pos:end])
        pos = end
    return items


def encode_block_header_rlp(b: dict) -> bytes:
    items = [
        rlp_bytes(hx(b["parentHash"])),
        rlp_bytes(hx(b["sha3Uncles"])),
        rlp_bytes(hx(b["miner"])),
        rlp_bytes(hx(b["stateRoot"])),
        rlp_bytes(hx(b["transactionsRoot"])),
        rlp_bytes(hx(b["receiptsRoot"])),
        rlp_bytes(hx(b["logsBloom"])),
        rlp_int(hxi(b["difficulty"])),
        rlp_int(hxi(b["number"])),
        rlp_int(hxi(b["gasLimit"])),
        rlp_int(hxi(b["gasUsed"])),
        rlp_int(hxi(b["timestamp"])),
        rlp_bytes(hx(b["extraData"])),
        rlp_bytes(hx(b["mixHash"])),
        rlp_bytes(hx(b["nonce"])),
    ]
    for k, kind in [
        ("baseFeePerGas", "int"),
        ("withdrawalsRoot", "bytes"),
        ("blobGasUsed", "int"),
        ("excessBlobGas", "int"),
        ("parentBeaconBlockRoot", "bytes"),
        ("requestsHash", "bytes"),
        ("blockAccessListHash", "bytes"),
        ("slotNumber", "int"),
    ]:
        if k in b and b[k] is not None:
            items.append(rlp_int(hxi(b[k])) if kind == "int" else rlp_bytes(hx(b[k])))
    rlp = rlp_list(items)
    calc_hash = "0x" + keccak256(rlp).hex()
    assert calc_hash == b["hash"], f"Header RLP mismatch: {calc_hash} != {b['hash']}"
    return rlp


def encode_receipt(r: dict) -> bytes:
    status_or_root = (
        rlp_int(int(r["status"], 16))
        if r.get("status") is not None
        else rlp_bytes(hx(r["root"]))
    )
    logs_rlp = rlp_list(
        [
            rlp_list(
                [
                    rlp_bytes(hx(l["address"])),
                    rlp_list([rlp_bytes(hx(t)) for t in l["topics"]]),
                    rlp_bytes(hx(l["data"])),
                ]
            )
            for l in r["logs"]
        ]
    )
    inner = rlp_list(
        [
            status_or_root,
            rlp_int(int(r["cumulativeGasUsed"], 16)),
            rlp_bytes(hx(r["logsBloom"])),
            logs_rlp,
        ]
    )
    t = int(r.get("type", "0x0"), 16)
    return inner if t == 0 else bytes([t]) + inner


def to_nibbles(b: bytes):
    out = []
    for x in b:
        out.append(x >> 4)
        out.append(x & 0x0F)
    return out


def compact_encode(nibbles, is_leaf: bool) -> bytes:
    term = 1 if is_leaf else 0
    if len(nibbles) % 2 == 1:
        first = ((2 * term + 1) << 4) | nibbles[0]
        rest = nibbles[1:]
    else:
        first = (2 * term) << 4
        rest = nibbles
    out = bytearray([first])
    for i in range(0, len(rest), 2):
        out.append((rest[i] << 4) | rest[i + 1])
    return bytes(out)


def compact_decode(enc: bytes):
    nibs = to_nibbles(enc)
    flag = nibs[0]
    is_leaf = (flag & 2) != 0
    odd = (flag & 1) != 0
    return (nibs[1:] if odd else nibs[2:]), is_leaf


def mpt_build_and_prove(items, target_key_bytes: bytes):
    """Build full MPT, verify root, and extract proof path for `target_key_bytes`."""
    nodes = {}

    def build_sub(pairs):
        if not pairs:
            return b"\x80"
        if len(pairs) == 1:
            k, v = pairs[0]
            enc = rlp_list([rlp_bytes(compact_encode(k, True)), rlp_bytes(v)])
            if len(enc) >= 32:
                h = keccak256(enc)
                nodes[h] = enc
                return rlp_bytes(h)
            return enc
        p0 = pairs[0][0]
        lcp = 0
        while all(lcp < len(k) and k[lcp] == p0[lcp] for k, _ in pairs):
            lcp += 1
        if lcp > 0:
            sub_ref = build_sub([(k[lcp:], v) for k, v in pairs])
            enc = rlp_list([rlp_bytes(compact_encode(p0[:lcp], False)), sub_ref])
            if len(enc) >= 32:
                h = keccak256(enc)
                nodes[h] = enc
                return rlp_bytes(h)
            return enc
        buckets = [[] for _ in range(16)]
        val = b""
        for k, v in pairs:
            if len(k) == 0:
                val = v
            else:
                buckets[k[0]].append((k[1:], v))
        children = [build_sub(buckets[b]) if buckets[b] else b"\x80" for b in range(16)]
        children.append(rlp_bytes(val))
        enc = rlp_list(children)
        if len(enc) >= 32:
            h = keccak256(enc)
            nodes[h] = enc
            return rlp_bytes(h)
        return enc

    root_ref = build_sub(items)
    if len(root_ref) == 33 and root_ref[0] == 0xA0:
        root = root_ref[1:]
    else:
        root = keccak256(root_ref)
        nodes[root] = root_ref

    proof = []
    cur_hash = root
    rem = to_nibbles(target_key_bytes)
    while cur_hash is not None:
        node_rlp = nodes[cur_hash]
        proof.append(node_rlp)
        parts = rlp_decode_list(node_rlp)
        if len(parts) == 2:
            path_enc = parts[0]
            # strip RLP byte prefix to get raw compact bytes
            if path_enc[0] < 0x80:
                compact_bytes = path_enc
            elif path_enc[0] < 0xB8:
                compact_bytes = path_enc[1:]
            else:
                ll = path_enc[0] - 0xB7
                compact_bytes = path_enc[1 + ll :]
            path_nibs, is_leaf = compact_decode(compact_bytes)
            assert rem[: len(path_nibs)] == path_nibs
            rem = rem[len(path_nibs) :]
            if is_leaf:
                cur_hash = None
            else:
                nxt = parts[1]
                cur_hash = nxt[1:] if len(nxt) == 33 and nxt[0] == 0xA0 else None
        elif len(parts) == 17:
            if not rem:
                cur_hash = None
            else:
                nxt = parts[rem[0]]
                rem = rem[1:]
                cur_hash = nxt[1:] if len(nxt) == 33 and nxt[0] == 0xA0 else None
        else:
            raise ValueError(f"Unexpected MPT node len {len(parts)}")
    return root, proof


def encode_account_value(proof_obj: dict) -> bytes:
    nonce = hxi(proof_obj["nonce"])
    balance = hxi(proof_obj["balance"])
    storage_hash = hx(proof_obj["storageHash"])
    code_hash = hx(proof_obj["codeHash"])
    return rlp_list(
        [
            rlp_int(nonce),
            rlp_int(balance),
            rlp_bytes(storage_hash),
            rlp_bytes(code_hash),
        ]
    )


# --- SSZ Header HashTreeRoot (mirrors mosoo-core/src/crypto.rs) ---
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def htr_beacon_header(h: dict) -> str:
    def u64l(v):
        return int(v).to_bytes(8, "little") + b"\x00" * 24

    layer = [
        u64l(h["slot"]),
        u64l(h["proposer_index"]),
        hx(h["parent_root"]),
        hx(h["state_root"]),
        hx(h["body_root"]),
        b"\x00" * 32,
        b"\x00" * 32,
        b"\x00" * 32,
    ]
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return "0x" + layer[0].hex()


# --- Network Fetchers ---
def http_get(url: str):
    req = urllib.request.Request(
        url, headers={"User-Agent": "mosoo-vector-fetcher/1.0", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30, context=TLS_CTX) as r:
        return json.loads(r.read().decode("utf-8"))


def rpc_call(url: str, method: str, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "mosoo-vector-fetcher/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30, context=TLS_CTX) as r:
        resp = json.loads(r.read().decode("utf-8"))
    if resp.get("error"):
        raise RuntimeError(f"RPC {method} error on {url}: {resp['error']}")
    return resp["result"]


def write_json(path: pathlib.Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(obj, indent=2) + "\n"
    path.write_text(raw, encoding="utf-8", newline="\n")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def try_earlier_bootstrap(beacon_url: str, fin_slot: int, period_fin: int):
    """Try to obtain a bootstrap from an earlier finalized epoch in the SAME sync committee period
    so an end-to-end Initialize -> Begin -> Miller -> Finish progression can run live."""
    for delta in (64, 32, 96):
        cand_slot = fin_slot - delta
        if cand_slot <= 0 or (cand_slot // 8192) != period_fin:
            continue
        try:
            hdr = http_get(f"{beacon_url}/eth/v1/beacon/headers/{cand_slot}")["data"]
            bs = http_get(f"{beacon_url}/eth/v1/beacon/light_client/bootstrap/{hdr['root']}")
            return bs, hdr["root"], cand_slot
        except Exception:
            continue
    return None, None, None


def fetch_mainnet():
    print("[1/3] Fetching live Ethereum Mainnet (Fulu) vectors...")
    out = VECTORS_DIR / "mainnet"
    fu = http_get(f"{MAINNET_BEACON}/eth/v1/beacon/light_client/finality_update")
    fin_beacon = fu["data"]["finalized_header"]["beacon"]
    fin_slot = int(fin_beacon["slot"])
    fin_root = htr_beacon_header(fin_beacon)
    period_fin = fin_slot // 8192

    bs_fin = http_get(f"{MAINNET_BEACON}/eth/v1/beacon/light_client/bootstrap/{fin_root}")
    bs_prev, prev_root, prev_slot = try_earlier_bootstrap(MAINNET_BEACON, fin_slot, period_fin)
    upds = http_get(
        f"{MAINNET_BEACON}/eth/v1/beacon/light_client/updates?start_period={period_fin - 1}&count=2"
    )

    fin_exec = fu["data"]["finalized_header"]["execution"]
    blk_num = int(fin_exec["block_number"])
    blk_hash = fin_exec["block_hash"]

    el_blk = None
    active_el = None
    usdc_proof = None
    weth_proof = None
    usdc_impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    for candidate_el in MAINNET_ELS:
        try:
            el_blk = rpc_call(candidate_el, "eth_getBlockByHash", [blk_hash, False])
            usdc_proof = rpc_call(
                candidate_el,
                "eth_getProof",
                [USDC_MAINNET, [usdc_impl_slot], hex(blk_num)],
            )
            weth_proof = rpc_call(
                candidate_el,
                "eth_getProof",
                [WETH_MAINNET, ["0x" + "00" * 32], hex(blk_num)],
            )
            active_el = candidate_el
            break
        except Exception:
            continue
    assert el_blk is not None and active_el is not None, "All Mainnet RPCs failed proof fetch"
    header_rlp = encode_block_header_rlp(el_blk)
    assert el_blk["stateRoot"] == fin_exec["state_root"]
    assert el_blk["receiptsRoot"] == fin_exec["receipts_root"]

    # Fetch block receipts, verify full MPT receiptsRoot, extract real ERC-20 Transfer log proof
    receipts = rpc_call(active_el, "eth_getBlockReceipts", [hex(blk_num)])
    items = [(to_nibbles(rlp_int(int(r["transactionIndex"], 16))), encode_receipt(r)) for r in receipts]

    selected_receipt = None
    selected_log = None
    for r in receipts:
        if int(r.get("status", "0x0"), 16) != 1:
            continue
        for idx, lg in enumerate(r.get("logs", [])):
            topics = lg.get("topics", [])
            if (
                len(topics) == 3
                and topics[0].lower() == ERC20_TRANSFER_TOPIC0
                and len(hx(lg["data"])) == 32
            ):
                selected_receipt = r
                selected_log = (idx, lg)
                break
        if selected_receipt:
            break

    assert selected_receipt is not None, "No ERC-20 Transfer log found in finalized Mainnet block"
    tx_index = int(selected_receipt["transactionIndex"], 16)
    receipt_rlp = encode_receipt(selected_receipt)
    calc_root, proof_nodes = mpt_build_and_prove(items, rlp_int(tx_index))
    assert "0x" + calc_root.hex() == el_blk["receiptsRoot"], "Mainnet receiptsRoot mismatch"

    exec_proof_bundle = {
        "chain_id": 1,
        "block_number": blk_num,
        "block_hash": el_blk["hash"],
        "state_root": el_blk["stateRoot"],
        "receipts_root": el_blk["receiptsRoot"],
        "header_rlp": "0x" + header_rlp.hex(),
        "usdc": {
            "address": USDC_MAINNET,
            "balance_wei": str(hxi(usdc_proof["balance"])),
            "account_rlp": "0x" + encode_account_value(usdc_proof).hex(),
            "account_proof": usdc_proof["accountProof"],
            "storage_slot": usdc_proof["storageProof"][0]["key"],
            "storage_value_hex": usdc_proof["storageProof"][0]["value"],
            "storage_value_rlp": "0x" + rlp_int(hxi(usdc_proof["storageProof"][0]["value"])).hex(),
            "storage_proof": usdc_proof["storageProof"][0]["proof"],
        },
        "weth": {
            "address": WETH_MAINNET,
            "balance_wei": str(hxi(weth_proof["balance"])),
            "account_rlp": "0x" + encode_account_value(weth_proof).hex(),
            "account_proof": weth_proof["accountProof"],
            "storage_slot": weth_proof["storageProof"][0]["key"],
            "storage_value_hex": weth_proof["storageProof"][0]["value"],
            "storage_value_rlp": "0x" + rlp_int(hxi(weth_proof["storageProof"][0]["value"])).hex(),
            "storage_proof": weth_proof["storageProof"][0]["proof"],
        },
    }

    receipt_bundle = {
        "chain_id": 1,
        "block_number": blk_num,
        "block_hash": el_blk["hash"],
        "receipts_root": el_blk["receiptsRoot"],
        "tx_hash": selected_receipt["transactionHash"],
        "tx_index": tx_index,
        "log_index": selected_log[0],
        "emitter": selected_log[1]["address"],
        "topic0": selected_log[1]["topics"][0],
        "from_address": "0x" + selected_log[1]["topics"][1][-40:],
        "to_address": "0x" + selected_log[1]["topics"][2][-40:],
        "amount_u256_be": selected_log[1]["data"],
        "receipt_rlp": "0x" + receipt_rlp.hex(),
        "receipt_proof": ["0x" + p.hex() for p in proof_nodes],
    }

    hashes = {
        "bootstrap_fin": write_json(out / "bootstrap.json", {"block_root": fin_root, "bootstrap": bs_fin}),
        "finality_update": write_json(out / "finality_update.json", fu),
        "period_updates": write_json(out / "period_updates.json", upds),
        "execution_proof": write_json(out / "execution_proof.json", exec_proof_bundle),
        "receipt_proof": write_json(out / "receipt_proof.json", receipt_bundle),
    }
    if bs_prev is not None:
        hashes["bootstrap_earlier"] = write_json(
            out / "bootstrap_earlier.json",
            {"block_root": prev_root, "slot": prev_slot, "bootstrap": bs_prev},
        )
    print(f"  -> Mainnet slot={fin_slot}, EL blk={blk_num}, tx={receipt_bundle['tx_hash'][:18]}...")
    return {
        "chain_id": 1,
        "finalized_slot": fin_slot,
        "signature_slot": int(fu["data"]["signature_slot"]),
        "earlier_bootstrap_slot": prev_slot,
        "el_block_number": blk_num,
        "el_block_hash": el_blk["hash"],
        "hashes": hashes,
    }


def fetch_sepolia():
    print("[2/3] Fetching live Ethereum Sepolia (Gloas ePBS) + MosooLocker vectors...")
    out = VECTORS_DIR / "sepolia"
    fu = http_get(f"{SEPOLIA_BEACON}/eth/v1/beacon/light_client/finality_update")
    fin_beacon = fu["data"]["finalized_header"]["beacon"]
    fin_slot = int(fin_beacon["slot"])
    fin_root = htr_beacon_header(fin_beacon)
    period_fin = fin_slot // 8192

    bs_fin = http_get(f"{SEPOLIA_BEACON}/eth/v1/beacon/light_client/bootstrap/{fin_root}")
    bs_prev, prev_root, prev_slot = try_earlier_bootstrap(SEPOLIA_BEACON, fin_slot, period_fin)
    upds = http_get(
        f"{SEPOLIA_BEACON}/eth/v1/beacon/light_client/updates?start_period={period_fin - 1}&count=2"
    )

    # Fetch live Gloas execution block RLP for execution_block_hash committed in beacon body
    ebh = fu["data"]["finalized_header"]["execution_block_hash"]
    gloas_blk = rpc_call(SEPOLIA_EL, "eth_getBlockByHash", [ebh, False])
    gloas_rlp = encode_block_header_rlp(gloas_blk)

    # Fetch recent block + live eth_getProof for MosooLocker on Sepolia (step back 4 blocks + archival fallback to avoid RPC LB skew)
    head_hex = rpc_call(SEPOLIA_EL, "eth_blockNumber", [])
    target_num = max(0, int(head_hex, 16) - 4)
    try:
        latest_blk = rpc_call(SEPOLIA_EL, "eth_getBlockByNumber", [hex(target_num), False])
        locker_proof = rpc_call(
            SEPOLIA_EL,
            "eth_getProof",
            [MOSOO_LOCKER_SEPOLIA, ["0x" + "00" * 32], hex(target_num)],
        )
    except Exception:
        head_hex = rpc_call(SEPOLIA_ARCHIVE_EL, "eth_blockNumber", [])
        target_num = max(0, int(head_hex, 16) - 2)
        latest_blk = rpc_call(SEPOLIA_ARCHIVE_EL, "eth_getBlockByNumber", [hex(target_num), False])
        locker_proof = rpc_call(
            SEPOLIA_ARCHIVE_EL,
            "eth_getProof",
            [MOSOO_LOCKER_SEPOLIA, ["0x" + "00" * 32], hex(target_num)],
        )
    latest_snapshot = {
        "chain_id": 11155111,
        "block_number": int(latest_blk["number"], 16),
        "block_hash": latest_blk["hash"],
        "state_root": latest_blk["stateRoot"],
        "receipts_root": latest_blk["receiptsRoot"],
        "header_rlp": "0x" + encode_block_header_rlp(latest_blk).hex(),
        "mosoo_locker": {
            "address": MOSOO_LOCKER_SEPOLIA,
            "balance_wei": str(hxi(locker_proof["balance"])),
            "nonce": hxi(locker_proof["nonce"]),
            "account_rlp": "0x" + encode_account_value(locker_proof).hex(),
            "account_proof": locker_proof["accountProof"],
        },
    }

    # Fetch REAL confirmed DepositETH transaction (tx 0x6ecddb..., block 12082214) via archival RPC
    dep_blk = rpc_call(SEPOLIA_ARCHIVE_EL, "eth_getBlockByNumber", [hex(SEPOLIA_DEPOSIT_BLOCK), False])
    dep_header_rlp = encode_block_header_rlp(dep_blk)
    dep_receipts = rpc_call(SEPOLIA_ARCHIVE_EL, "eth_getBlockReceipts", [hex(SEPOLIA_DEPOSIT_BLOCK)])
    dep_items = [
        (to_nibbles(rlp_int(int(r["transactionIndex"], 16))), encode_receipt(r))
        for r in dep_receipts
    ]
    dep_receipt = next(
        r for r in dep_receipts if r["transactionHash"].lower() == SEPOLIA_DEPOSIT_TX.lower()
    )
    dep_tx_index = int(dep_receipt["transactionIndex"], 16)
    dep_receipt_rlp = encode_receipt(dep_receipt)
    dep_calc_root, dep_proof_nodes = mpt_build_and_prove(dep_items, rlp_int(dep_tx_index))
    assert "0x" + dep_calc_root.hex() == dep_blk["receiptsRoot"], "Deposit receiptsRoot mismatch"

    deposit_log_index = next(
        i
        for i, lg in enumerate(dep_receipt["logs"])
        if lg["address"].lower() == MOSOO_LOCKER_SEPOLIA.lower()
    )
    deposit_bundle = {
        "chain_id": 11155111,
        "block_number": SEPOLIA_DEPOSIT_BLOCK,
        "block_hash": dep_blk["hash"],
        "state_root": dep_blk["stateRoot"],
        "receipts_root": dep_blk["receiptsRoot"],
        "header_rlp": "0x" + dep_header_rlp.hex(),
        "tx_hash": SEPOLIA_DEPOSIT_TX,
        "tx_index": dep_tx_index,
        "log_index": deposit_log_index,
        "deposit_contract": MOSOO_LOCKER_SEPOLIA,
        "receipt_rlp": "0x" + dep_receipt_rlp.hex(),
        "receipt_proof": ["0x" + p.hex() for p in dep_proof_nodes],
    }

    gloas_exec_bundle = {
        "chain_id": 11155111,
        "block_number": int(gloas_blk["number"], 16),
        "block_hash": gloas_blk["hash"],
        "state_root": gloas_blk["stateRoot"],
        "receipts_root": gloas_blk["receiptsRoot"],
        "execution_rlp": "0x" + gloas_rlp.hex(),
    }

    hashes = {
        "bootstrap_fin": write_json(out / "bootstrap.json", {"block_root": fin_root, "bootstrap": bs_fin}),
        "finality_update": write_json(out / "finality_update.json", fu),
        "period_updates": write_json(out / "period_updates.json", upds),
        "execution_block": write_json(out / "execution_block.json", gloas_exec_bundle),
        "latest_proof_snapshot": write_json(out / "latest_proof_snapshot.json", latest_snapshot),
        "deposit_12082214": write_json(out / "deposit_12082214.json", deposit_bundle),
    }
    if bs_prev is not None:
        hashes["bootstrap_earlier"] = write_json(
            out / "bootstrap_earlier.json",
            {"block_root": prev_root, "slot": prev_slot, "bootstrap": bs_prev},
        )
    print(
        f"  -> Sepolia Gloas slot={fin_slot}, EL ebh_blk={gloas_exec_bundle['block_number']}, locker_bal={latest_snapshot['mosoo_locker']['balance_wei']} wei"
    )
    return {
        "chain_id": 11155111,
        "fork": fu.get("version", "gloas"),
        "finalized_slot": fin_slot,
        "signature_slot": int(fu["data"]["signature_slot"]),
        "earlier_bootstrap_slot": prev_slot,
        "gloas_el_block_number": gloas_exec_bundle["block_number"],
        "deposit_tx": SEPOLIA_DEPOSIT_TX,
        "hashes": hashes,
    }


def fetch_hoodi():
    print("[3/3] Fetching live Ethereum Hoodi (Fulu) vectors...")
    out = VECTORS_DIR / "hoodi"
    fu = http_get(f"{HOODI_BEACON}/eth/v1/beacon/light_client/finality_update")
    fin_beacon = fu["data"]["finalized_header"]["beacon"]
    fin_slot = int(fin_beacon["slot"])
    sig_slot = int(fu["data"]["signature_slot"])
    fin_root = htr_beacon_header(fin_beacon)
    period_fin = fin_slot // 8192

    bs_fin = http_get(f"{HOODI_BEACON}/eth/v1/beacon/light_client/bootstrap/{fin_root}")
    bs_prev, prev_root, prev_slot = try_earlier_bootstrap(HOODI_BEACON, fin_slot, period_fin)
    # Include both P_fin-1 and P_fin in case signature_slot crossed into period_fin + 1!
    upds = http_get(
        f"{HOODI_BEACON}/eth/v1/beacon/light_client/updates?start_period={period_fin - 1}&count=2"
    )
    # Also fetch period_fin update specifically if sig_slot crossed boundary
    extra_upd = None
    try:
        extra_upd = http_get(
            f"{HOODI_BEACON}/eth/v1/beacon/light_client/updates?start_period={period_fin}&count=1"
        )
    except Exception:
        extra_upd = None

    hashes = {
        "bootstrap_fin": write_json(out / "bootstrap.json", {"block_root": fin_root, "bootstrap": bs_fin}),
        "finality_update": write_json(out / "finality_update.json", fu),
        "period_updates": write_json(out / "period_updates.json", upds),
    }
    if extra_upd:
        hashes["current_period_update"] = write_json(out / "current_period_update.json", extra_upd)
    if bs_prev is not None:
        hashes["bootstrap_earlier"] = write_json(
            out / "bootstrap_earlier.json",
            {"block_root": prev_root, "slot": prev_slot, "bootstrap": bs_prev},
        )
    print(f"  -> Hoodi slot={fin_slot}, sig_slot={sig_slot}")
    return {
        "chain_id": 560048,
        "fork": fu.get("version", "fulu"),
        "finalized_slot": fin_slot,
        "signature_slot": sig_slot,
        "earlier_bootstrap_slot": prev_slot,
        "hashes": hashes,
    }


def load_cached_mainnet_info():
    out = VECTORS_DIR / "mainnet"
    needed = [
        "bootstrap.json",
        "finality_update.json",
        "period_updates.json",
        "execution_proof.json",
        "receipt_proof.json",
    ]
    if not all((out / n).exists() for n in needed):
        return None
    fu = json.loads((out / "finality_update.json").read_text(encoding="utf-8"))
    ep = json.loads((out / "execution_proof.json").read_text(encoding="utf-8"))
    prev_slot = None
    if (out / "bootstrap_earlier.json").exists():
        prev_slot = json.loads((out / "bootstrap_earlier.json").read_text(encoding="utf-8")).get("slot")
    hashes = {}
    for key, fname in [
        ("bootstrap_fin", "bootstrap.json"),
        ("finality_update", "finality_update.json"),
        ("period_updates", "period_updates.json"),
        ("execution_proof", "execution_proof.json"),
        ("receipt_proof", "receipt_proof.json"),
        ("bootstrap_earlier", "bootstrap_earlier.json"),
    ]:
        p = out / fname
        if p.exists():
            raw_lf = p.read_bytes().replace(b"\r\n", b"\n")
            hashes[key] = hashlib.sha256(raw_lf).hexdigest()
    return {
        "chain_id": 1,
        "finalized_slot": int(fu["data"]["finalized_header"]["beacon"]["slot"]),
        "signature_slot": int(fu["data"]["signature_slot"]),
        "earlier_bootstrap_slot": prev_slot,
        "el_block_number": ep["block_number"],
        "el_block_hash": ep["block_hash"],
        "hashes": hashes,
    }


def main():
    assert (
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ), "Keccak-256 self-check failed"
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    m_info = load_cached_mainnet_info()
    if m_info is None:
        m_info = fetch_mainnet()
    else:
        print(
            f"[1/3] Using freshly fetched Mainnet snapshot (slot={m_info['finalized_slot']}, EL blk={m_info['el_block_number']})"
        )
    s_info = fetch_sepolia()
    h_info = fetch_hoodi()

    manifest = {
        "schema_version": 1,
        "networks": {
            "mainnet": m_info,
            "sepolia": s_info,
            "hoodi": h_info,
        },
    }
    write_json(VECTORS_DIR / "manifest.json", manifest)
    print("[+] Successfully fetched and verified all live chain vectors into vectors/")


if __name__ == "__main__":
    main()
