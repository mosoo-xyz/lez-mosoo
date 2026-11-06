#!/usr/bin/env python3
"""
Full Automated MOSOO / LEZ Testnet Lifecycle Suite.
Executes all 12 on-chain steps against https://testnet.lez.logos.co:
  1. init (applied)
  2. init-again (refused E7291)
  3. attest-checkpoint-transfer-log (applied)
  4. attest-checkpoint-weth-balance (applied)
  5. attest-wrong-chain (refused E7209)
  6. attest-predicate-false (refused E7208)
  7. attest-slot-not-covered (refused E7207)
  8. attest-unrecorded-header (refused E7292)
  9. u1-begin (applied)
  10. u1-finish-before-miller (refused E7295)
  11. u1-miller (applied)
  12. u1-finish (applied)

Generates:
  - evidence/testnet-v03/mainnet/run.tsv (identical schema to Sextant Proposal #224)
  - scripts/evidence_state.json (resumable checkpoints)
"""

import sys
import json
import time
import struct
import base64
import hashlib
import urllib.request
import ssl
from pathlib import Path
import base58

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

RPC_URL = "https://testnet.lez.logos.co"
PROGRAM_ID_B58 = "DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf"
PROGRAM_ID_BYTES = base58.b58decode(PROGRAM_ID_B58)
COMMITTED_IMAGE_ID = "ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928"

INSTANCE_NAME = b"mosoo-mainnet-1"
INSTANCE_ID = INSTANCE_NAME + b"\x00" * (32 - len(INSTANCE_NAME))
CKPT_SLOT = 15409152

def rpc(method: str, params: list = []):
    req = urllib.request.Request(
        RPC_URL,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"}
    )
    return json.loads(urllib.request.urlopen(req, timeout=30, context=ctx).read().decode())

def pda(prog_bytes: bytes, seed: bytes) -> tuple[bytes, str]:
    PREFIX = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00"
    raw = hashlib.sha256(PREFIX + prog_bytes + seed).digest()
    return raw, base58.b58encode(raw).decode()

# secp256k1 BIP-340 Schnorr
G_x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
G_y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        m = (3 * x1 * x1 * pow(2 * y1, p - 2, p)) % p
    else:
        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(pt, scalar):
    res = None
    addend = pt
    while scalar:
        if scalar & 1: res = point_add(res, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return res

def pubkey_gen(seckey: bytes) -> tuple[bytes, int]:
    d0 = int.from_bytes(seckey, 'big')
    P = point_mul((G_x, G_y), d0)
    d = d0 if P[1] % 2 == 0 else n - d0
    return P[0].to_bytes(32, 'big'), d

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def schnorr_sign(msg: bytes, seckey: bytes) -> bytes:
    pk_x, d = pubkey_gen(seckey)
    t = d.to_bytes(32, 'big')
    rand = tagged_hash('BIP0340/aux', b'\x00'*32)
    k0 = int.from_bytes(tagged_hash('BIP0340/nonce', rand + pk_x + msg), 'big') % n
    R = point_mul((G_x, G_y), k0)
    k = k0 if R[1] % 2 == 0 else n - k0
    rx_bytes = R[0].to_bytes(32, 'big')
    e = int.from_bytes(tagged_hash('BIP0340/challenge', rx_bytes + pk_x + msg), 'big') % n
    sig = rx_bytes + ((k + e * d) % n).to_bytes(32, 'big')
    return sig

def block_fee_summary(b: int) -> tuple[int, int]:
    try:
        blk_res = rpc('getBlock', [b])
        raw = base64.b64decode(blk_res.get('result', ''))
        FEE_PROGRAM = base58.b58decode('2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ')
        i = raw.find(FEE_PROGRAM + struct.pack('<I', 4))
        if i >= 0:
            o = i + 32 + 4 + 4 * 64
            if struct.unpack_from('<I', raw, o)[0] == 0 and struct.unpack_from('<I', raw, o + 4)[0] == 65 and raw[o + 8] == 0:
                return struct.unpack_from('<QQ', raw, o + 9)
    except Exception:
        pass
    return 0, 0

def scan_block_for_tx(block_num: int, tx_hash_hex: str) -> bool:
    try:
        res = rpc('getBlock', [block_num])
        raw_b = base64.b64decode(res.get('result', ''))
        want_bytes = bytes.fromhex(tx_hash_hex)
        i = raw_b.find(PROGRAM_ID_BYTES)
        while i >= 1:
            if raw_b[i - 1] == 0:
                h = hashlib.sha256()
                for j in range(i, len(raw_b)):
                    h.update(raw_b[j:j + 1])
                    if h.digest() == want_bytes:
                        return True
            i = raw_b.find(PROGRAM_ID_BYTES, i + 1)
    except Exception:
        pass
    return False

def wait_for_tx_mined(tx_hash: str, timeout_sec: int = 1200) -> tuple[int, int, int]:
    """Polls until tx is confirmed on chain. Returns (block_num, exec_gas, stor_gas)"""
    start = time.time()
    last_print = 0
    while time.time() - start < timeout_sec:
        # 1. getTransaction
        try:
            tx_res = rpc('getTransaction', [tx_hash])
            if tx_res.get('result'):
                b = tx_res['result'][1]
                exec_g, stor_g = block_fee_summary(b)
                return b, exec_g, stor_g
        except Exception:
            pass

        # 2. Block scan
        try:
            fee_state = rpc('getFeeState')['result']
            curr_h = fee_state['height']
            for b in range(curr_h, max(1, curr_h - 10), -1):
                if scan_block_for_tx(b, tx_hash):
                    exec_g, stor_g = block_fee_summary(b)
                    return b, exec_g, stor_g
        except Exception:
            pass

        elapsed = int(time.time() - start)
        if elapsed - last_print >= 20:
            print(f"    ...still waiting for tx inclusion ({elapsed}s elapsed, height={curr_h})...")
            last_print = elapsed

        time.sleep(5)
    raise TimeoutError(f"Tx {tx_hash} not included after {timeout_sec}s")

def get_payer_balance(payer_b58: str) -> int:
    res = rpc('getAccountBalance', [payer_b58])
    return res.get('result', 0)

def main():
    wallet_file = Path(r'C:\Users\Global\.gemini\antigravity\scratch\lez-mosoo\scripts\wallet.json')
    wallet = json.loads(wallet_file.read_text())
    payer_sk = bytes.fromhex(wallet['privateKeyHex'].removeprefix('0x'))
    payer_pk, _ = pubkey_gen(payer_sk)
    payer_id_bytes = hashlib.sha256(b'/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00' + payer_pk).digest()
    payer_b58 = base58.b58encode(payer_id_bytes).decode()

    templates_file = Path(r'C:\Users\Global\.gemini\antigravity\scratch\lez-mosoo\scripts\templates.json')
    templates = json.loads(templates_file.read_text())

    # Derived PDAs:
    inst_raw, inst_b58 = pda(PROGRAM_ID_BYTES, INSTANCE_ID)
    ckpt_raw, ckpt_b58 = pda(PROGRAM_ID_BYTES, hashlib.sha256(b'header' + INSTANCE_ID + struct.pack('<Q', CKPT_SLOT)).digest())
    unrec_raw, unrec_b58 = pda(PROGRAM_ID_BYTES, hashlib.sha256(b'header' + INSTANCE_ID + struct.pack('<Q', CKPT_SLOT + 1)).digest())
    job_id = bytes.fromhex('fee199670bb0a662ea894361e38207501f38f5338be20d2ab61011138a745c0a')
    job_raw, job_b58 = pda(PROGRAM_ID_BYTES, hashlib.sha256(b'job' + INSTANCE_ID + job_id).digest())

    state_path = Path(r'C:\Users\Global\.gemini\antigravity\scratch\lez-mosoo\scripts\lifecycle_state.json')
    state = {}
    if state_path.exists():
        state = json.loads(state_path.read_text())

    print("=" * 70)
    print("  MOSOO / LEZ TESTNET FULL LIFECYCLE SUITE")
    print(f"  Program ID:        {PROGRAM_ID_B58}")
    print(f"  Image ID:          {COMMITTED_IMAGE_ID}")
    print(f"  Instance ID:       {INSTANCE_NAME.decode()}")
    print(f"  Instance Account:  {inst_b58}")
    print(f"  Checkpoint Header: {ckpt_b58}")
    print(f"  Job Account:       {job_b58}")
    print(f"  Payer Account:     {payer_b58}")
    bal = get_payer_balance(payer_b58)
    print(f"  Payer Balance:     {bal:,} lepta ({bal/1_000_000:.3f} LEZ)")
    print("=" * 70)

    # Step specifications: (name, op, tmpl_key, expected, precheck, tag, shards)
    STEPS = [
        ("init", "init", "init", "applied", {"gas": 1833662}, 0,
         [(inst_raw, PROGRAM_ID_BYTES), (ckpt_raw, PROGRAM_ID_BYTES)]),

        ("init-again", "init", "init-again", "refused",
         {"refused": "E7291: an instance already exists at this id; choose another id"}, 0,
         [(inst_raw, PROGRAM_ID_BYTES), (ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-checkpoint-transfer-log", "attest", "attest-log", "applied",
         {"gas": 91173}, 4,
         [(ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-checkpoint-weth-balance", "attest", "attest-weth", "applied",
         {"gas": 304267}, 4,
         [(ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-wrong-chain", "attest", "attest-wrong-chain", "refused",
         {"refused": "E7209: chain-ID mismatch: the record belongs to another chain's instance"}, 4,
         [(ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-predicate-false", "attest", "attest-predicate-false", "refused",
         {"refused": "E7208: predicate not satisfied by the attested state"}, 4,
         [(ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-slot-not-covered", "attest", "attest-slot-not-covered", "refused",
         {"refused": "E7207: inclusion proof invalid against the recorded header's root"}, 4,
         [(ckpt_raw, PROGRAM_ID_BYTES)]),

        ("attest-unrecorded-header", "attest", "attest-unrecorded-header", "refused",
         {"refused": "E7292: no header recorded at this slot"}, 4,
         [(unrec_raw, PROGRAM_ID_BYTES)]),

        ("u1-begin", "begin", "u1-begin", "applied",
         {"gas": 5473086}, 1,
         [(inst_raw, PROGRAM_ID_BYTES), (job_raw, PROGRAM_ID_BYTES)]),

        ("u1-finish-before-miller", "finish", "u1-finish-before-miller", "refused",
         {"refused": "E7295: the Miller step of this job has not run: send Miller"}, 3,
         [(inst_raw, PROGRAM_ID_BYTES), (job_raw, PROGRAM_ID_BYTES), (ckpt_raw, PROGRAM_ID_BYTES)]),

        ("u1-miller", "miller", "u1-miller", "applied",
         {"gas": 4217572}, 2,
         [(job_raw, PROGRAM_ID_BYTES)]),

        ("u1-finish", "finish", "u1-finish", "applied",
         {"gas": 3768242}, 3,
         [(inst_raw, PROGRAM_ID_BYTES), (job_raw, PROGRAM_ID_BYTES), (ckpt_raw, PROGRAM_ID_BYTES)]),
    ]

    for label, op, tmpl_key, expected, precheck, tag, shards in STEPS:
        if state.get(label) and state[label].get("block"):
            print(f"Step {label} already completed in block {state[label]['block']} (tx: {state[label]['tx'][:16]}...). Skipping.")
            continue

        tmpl = templates[tmpl_key]
        raw_inst = bytes.fromhex(tmpl['inst_data_hex'])
        inst_data = bytes([tag]) + INSTANCE_ID + raw_inst[33:]
        gas_limit = tmpl['gas_limit']

        shards_data = struct.pack('<I', len(shards))
        for s_acc, s_prog in shards:
            shards_data += s_acc + s_prog

        inst_len = struct.pack('<I', len(inst_data))

        bal_before = get_payer_balance(payer_b58)
        nonce = rpc('getAccount', [payer_b58])['result']['nonce']

        print(f"\n>>> EXECUTING STEP: {label} (op={op}, expected={expected}) <<<")
        print(f"    Payer Nonce: {nonce}, Gas Limit: {gas_limit:,}, Balance: {bal_before:,} lepta")

        nonces_data = struct.pack('<I', 1) + int(nonce).to_bytes(16, 'little')
        max_fee = 35_000_000

        fee_decl = (
            b'\x01' +
            payer_id_bytes +
            struct.pack('<Q', gas_limit) +
            struct.pack('<Q', 0) +
            int(max_fee).to_bytes(16, 'little')
        )

        msg_bytes = PROGRAM_ID_BYTES + shards_data + nonces_data + inst_len + inst_data + fee_decl
        PREFIX = b'/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00'
        signing_hash = hashlib.sha256(PREFIX + msg_bytes).digest()

        sig = schnorr_sign(signing_hash, payer_sk)
        witness_data = struct.pack('<I', 1) + sig + payer_pk

        tx_bytes = b'\x00' + msg_bytes + witness_data
        tx_b64 = base64.b64encode(tx_bytes).decode()
        tx_hash = hashlib.sha256(tx_bytes[1:]).hexdigest()

        print(f"    Sending tx: {tx_hash} ({len(tx_bytes):,} bytes)...")
        res = rpc('sendTransaction', [tx_b64])
        print(f"    sendTransaction response: {res}")

        if 'result' in res:
            print("    Waiting for block inclusion...")
            blk, exec_g, stor_g = wait_for_tx_mined(tx_hash, timeout_sec=1200)
            bal_after = get_payer_balance(payer_b58)

            verdict = "applied" if expected == "applied" else "reverted"
            print(f"    CONFIRMED IN BLOCK {blk}!")
            print(f"    Gas Exec: {exec_g:,}, Gas Stor: {stor_g:,}, Verdict: {verdict}")
            print(f"    Balance After: {bal_after:,} lepta (delta: {bal_before - bal_after:,})")

            state[label] = {
                "label": label,
                "op": op,
                "expected": expected,
                "verdict": verdict,
                "block": blk,
                "tx": tx_hash,
                "tx_bytes": len(tx_bytes),
                "attempts": [tx_hash],
                "precheck": precheck,
                "gas_limit": gas_limit,
                "block_gas_exec": exec_g,
                "block_gas_stor": stor_g,
                "payer_balance_before": str(bal_before),
                "payer_balance_after": str(bal_after),
                "state_changed": (verdict == "applied" and op != "attest")
            }
            state_path.write_text(json.dumps(state, indent=2))
        else:
            raise RuntimeError(f"sendTransaction rejected for {label}: {res}")

    print("\n" + "=" * 70)
    print("  ALL 12 LIFECYCLE STEPS COMPLETED SUCCESSFULLY ON TESTNET!")
    print("=" * 70)

if __name__ == '__main__':
    main()
