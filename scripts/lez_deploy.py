#!/usr/bin/env python3
"""
LEZ v0.3.1 Pure-Python Program Deployer (Mosoo RFP-021)
========================================================
Implements the full LEZ public transaction protocol in Python:
  - Ed25519 signing
  - Borsh serialization of PublicTransaction / Message / WitnessSet
  - program_loader WriteSegment + CreateHeader instructions
  - sendTransaction / getTransaction / getAccountBalance RPC calls

No Rust, no Docker, no RISC Zero toolchain required.

Usage:
    python scripts/lez_deploy.py --elf artifacts/mosoo_lc.bin [--dry-run]
    python scripts/lez_deploy.py --check-balance

Reference:
    Logos Execution Zone source: github.com/logos-blockchain/logos-execution-zone rev db66590
    program_loader_core: lez/programs/program_loader/core/src/lib.rs
    lee public_transaction: lez/lee/src/public_transaction.rs
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
import time
import urllib.request
import ssl
from pathlib import Path

# ---------------------------------------------------------------------------
# Try optional imports
# ---------------------------------------------------------------------------
import base58 as _b58_mod

def b58decode(s):
    return _b58_mod.b58decode(s)

def b58encode(b):
    result = _b58_mod.b58encode(b)
    return result.decode() if isinstance(result, bytes) else result

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    print("[WARN] 'cryptography' not installed. Install with: pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RPC_URL   = "https://testnet.lez.logos.co"
WALLET_JSON = Path(__file__).parent / "wallet.json"
REPO_ROOT   = Path(__file__).parent.parent
EVIDENCE_DIR = REPO_ROOT / "evidence" / "testnet-v03" / "mainnet"

# program_loader account ID (all 0xFE bytes, base58 of [0xFE]*32)
PROGRAM_LOADER_ID_BYTES = bytes([0xFE] * 32)
PROGRAM_LOADER_ID       = b58encode(PROGRAM_LOADER_ID_BYTES)

# fee program
FEE_PROGRAM_ID = "2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ"

# Max bytes per segment chunk (from program_loader_core::MAX_SEGMENT_DATA_LEN)
MAX_SEGMENT_DATA_LEN = 96 * 1024   # 98,304 bytes

GAS_WRITE_SEGMENT = 500_000   # conservative limit per segment write
GAS_CREATE_HEADER = 500_000   # conservative limit for header creation
GAS_CAP           = 10_000_000

# ---------------------------------------------------------------------------
# TLS context (strict certificate verification)
# ---------------------------------------------------------------------------
_ctx = ssl.create_default_context()
# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------
def rpc(method: str, params=None):
    if params is None: params = []
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        RPC_URL, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mosoo-LEZ-Deploy/1.0"}
    )
    with urllib.request.urlopen(req, timeout=20, context=_ctx) as r:
        return json.loads(r.read().decode())


def get_balance(account_id: str) -> int:
    r = rpc("getAccountBalance", [account_id])
    return r.get("result", 0)


def get_nonce(account_id: str) -> int:
    """Returns current nonce (tx count) of account."""
    r = rpc("getAccountsNonces", [[account_id]])
    if "result" in r and r["result"]:
        v = r["result"][0]
        # nonce is a tuple [sequence, something] or just an int
        if isinstance(v, list): return v[0]
        return v
    # fallback: derive from account
    r2 = rpc("getAccount", [account_id])
    if "result" in r2:
        return r2["result"].get("nonce", 0)
    return 0


def get_fee_state():
    return rpc("getFeeState")["result"]


def send_transaction(tx_b58: str) -> str:
    """Send a base58-encoded Borsh transaction. Returns tx hash hex."""
    r = rpc("sendTransaction", [tx_b58])
    if "error" in r:
        raise RuntimeError(f"sendTransaction error: {r['error']}")
    return r["result"]


def wait_for_tx(tx_hash: str, timeout: int = 300) -> int | None:
    start = time.time()
    while time.time() - start < timeout:
        r = rpc("getTransaction", [tx_hash])
        if r.get("result") is not None:
            _, block = r["result"]
            return block
        time.sleep(5)
    return None


# ---------------------------------------------------------------------------
# Ed25519 key management
# ---------------------------------------------------------------------------
class LezKey:
    def __init__(self, privkey_hex: str):
        raw = bytes.fromhex(privkey_hex.removeprefix("0x"))
        self._sk = Ed25519PrivateKey.from_private_bytes(raw)
        pub_bytes = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_bytes = pub_bytes          # 32 bytes
        self.account_id   = b58encode(pub_bytes)   # base58

    def sign(self, message: bytes) -> bytes:
        """Returns 64-byte Ed25519 signature."""
        return self._sk.sign(message)


# ---------------------------------------------------------------------------
# Borsh helpers
# ---------------------------------------------------------------------------
def borsh_u32(n: int) -> bytes:   return struct.pack("<I", n)
def borsh_u64(n: int) -> bytes:   return struct.pack("<Q", n)
def borsh_u128(n: int) -> bytes:  return n.to_bytes(16, "little")
def borsh_bool(b: bool) -> bytes: return b"\x01" if b else b"\x00"
def borsh_option(v, encoder):     return b"\x01" + encoder(v) if v is not None else b"\x00"
def borsh_bytes(b: bytes) -> bytes:
    return borsh_u32(len(b)) + b
def borsh_vec(items, encoder) -> bytes:
    return borsh_u32(len(items)) + b"".join(encoder(x) for x in items)
def borsh_account_id(account_id_b58: str) -> bytes:
    raw = b58decode(account_id_b58)
    assert len(raw) == 32, f"AccountId must be 32 bytes, got {len(raw)} for {account_id_b58}"
    return raw


# ---------------------------------------------------------------------------
# program_loader Instruction encoding
# ---------------------------------------------------------------------------
def encode_write_segment(bytecode: bytes, next_segment_b58=None) -> bytes:
    """
    Instruction::WriteSegment { bytecode, next_segment }
    Borsh tag = 0x00000000 (u32 enum variant 0)
    
    Wait - Borsh encodes enum variants as u8 (single byte tag).
    From source: #[derive(BorshSerialize)] on enum = u8 tag for each variant.
    """
    tag = b"\x00"   # WriteSegment = variant 0
    data = tag
    data += borsh_bytes(bytecode)
    data += borsh_option(next_segment_b58, borsh_account_id)
    return data


def encode_create_header(first_segment_b58: str, immutable: bool = False) -> bytes:
    """Instruction::CreateHeader { first_segment, immutable }  — variant 1"""
    tag = b"\x01"
    data = tag
    data += borsh_account_id(first_segment_b58)
    data += borsh_bool(immutable)
    return data


# ---------------------------------------------------------------------------
# ProgramShardSelector encoding
# ---------------------------------------------------------------------------
def encode_shard_selector(account_id_b58: str, program_id_b58: str) -> bytes:
    """ProgramShardSelector { account_id: AccountId, program_account_id: AccountId }"""
    return borsh_account_id(account_id_b58) + borsh_account_id(program_id_b58)


# ---------------------------------------------------------------------------
# FeeDeclaration encoding
# ---------------------------------------------------------------------------
def encode_fee_declaration(payer_b58: str, gas_limit: int, gas_limit_stor: int, max_fee: int) -> bytes:
    """
    FeeDeclaration { payer: AccountId, gas_limit_exec: u64, gas_limit_stor: u64, max_fee: u128 }
    Option<FeeDeclaration> = Some(0x01) + data
    """
    data  = borsh_account_id(payer_b58)
    data += borsh_u64(gas_limit)
    data += borsh_u64(gas_limit_stor)
    data += borsh_u128(max_fee)
    return b"\x01" + data   # Some(fee_declaration)


# ---------------------------------------------------------------------------
# Message encoding
# ---------------------------------------------------------------------------
def encode_message(
    program_id_b58: str,
    shard_selectors: list,  # list of (account_id_b58, program_id_b58)
    nonces: list,           # list of Nonce values (u64)
    instruction_data: bytes,
    fee_declaration_bytes=None,  # pre-encoded Option<FeeDeclaration>
) -> bytes:
    """
    Message {
        program_account_id: AccountId,
        shard_selectors: Vec<ProgramShardSelector>,
        nonces: Vec<Nonce>,   // Nonce is a newtype over u64
        instruction_data: Vec<u8>,
        fee_declaration: Option<FeeDeclaration>,
    }
    """
    data  = borsh_account_id(program_id_b58)
    data += borsh_vec(shard_selectors, lambda s: encode_shard_selector(s[0], s[1]))
    data += borsh_vec(nonces, borsh_u64)
    data += borsh_bytes(instruction_data)
    if fee_declaration_bytes is None:
        data += b"\x00"  # None
    else:
        data += fee_declaration_bytes
    return data


# ---------------------------------------------------------------------------
# WitnessSet encoding
# ---------------------------------------------------------------------------
def encode_witness_set(signatures_and_pubkeys: list) -> bytes:
    """
    WitnessSet { signatures_and_public_keys: Vec<(Signature, PublicKey)> }
    Signature = [u8; 64], PublicKey = [u8; 32]
    """
    def encode_sig_pk(sig_pk):
        sig, pk = sig_pk
        assert len(sig) == 64, f"signature must be 64 bytes, got {len(sig)}"
        assert len(pk)  == 32, f"pubkey must be 32 bytes, got {len(pk)}"
        return sig + pk
    return borsh_vec(signatures_and_pubkeys, encode_sig_pk)


# ---------------------------------------------------------------------------
# PublicTransaction encoding
# ---------------------------------------------------------------------------
def encode_public_transaction(message_bytes: bytes, witness_set_bytes: bytes) -> bytes:
    """
    LeeTransaction::Public(PublicTransaction { message, witness_set })
    
    LeeTransaction enum variant 0 = Public (u8 tag = 0x00)
    PublicTransaction { message: Message, witness_set: WitnessSet }
    """
    lee_tx_tag = b"\x00"   # LeeTransaction::Public = variant 0
    return lee_tx_tag + message_bytes + witness_set_bytes


# ---------------------------------------------------------------------------
# Build & sign a program_loader public transaction
# ---------------------------------------------------------------------------
def build_program_loader_tx(
    key: LezKey,
    payer_id: str,
    instruction_data: bytes,
    target_accounts: list,  # [(account_id_b58, is_signer)]
    gas_limit: int,
    nonce: int,
    fee_state: dict,
) -> tuple[bytes, str]:
    """
    Build a signed LEZ PublicTransaction calling program_loader.
    
    Returns (raw_borsh_bytes, tx_hash_hex)
    
    The signing key signs both as the payer and (for segment/header targets) as the account owner.
    For WriteSegment: target is permissionless (no signature needed from target)
    For CreateHeader: target must be is_authorized — target key must sign
    
    Here we use same key for payer AND target accounts (single deployer).
    """
    loader_id = PROGRAM_LOADER_ID

    # Shard selectors: each target account selects the program_loader shard
    shard_selectors = [(acc_id, loader_id) for acc_id, _ in target_accounts]

    # Nonces: one per signer. The payer co-signs without joining shard selectors.
    # payer's nonce is the only one needed (payer co-signs separately).
    nonces = [nonce]

    # Fee declaration
    # max_fee = 2 * reserve; reserve = gas_limit * base_fee_exec + tx_bytes * base_fee_stor
    base_exec = fee_state["base_fee_exec"]
    base_stor  = fee_state["base_fee_stor"]
    # Rough tx size estimate (actual bytes computed after encoding, but we need max_fee before)
    estimated_stor = len(instruction_data) + 500
    reserve = gas_limit * base_exec + estimated_stor * base_stor
    max_fee = reserve * 2

    fee_decl = encode_fee_declaration(payer_id, gas_limit, 0, max_fee)

    # Build message (without signature — to get bytes to sign)
    msg_bytes = encode_message(
        program_id_b58    = loader_id,
        shard_selectors   = shard_selectors,
        nonces            = nonces,
        instruction_data  = instruction_data,
        fee_declaration_bytes = fee_decl,
    )

    # Sign the message
    # Both the payer and signers sign the same message bytes
    sig = key.sign(msg_bytes)
    pk  = key.public_bytes

    # WitnessSet: list of (sig, pubkey) for each signer
    # The payer co-signs without being in shard_selectors, so its sig goes in witness set
    witness = encode_witness_set([(sig, pk)])

    # Full transaction
    tx_bytes = encode_public_transaction(msg_bytes, witness)

    # TX hash = SHA-256 of tx_bytes AFTER the LeeTransaction variant tag byte
    tx_hash = hashlib.sha256(tx_bytes[1:]).hexdigest()

    return tx_bytes, tx_hash


# ---------------------------------------------------------------------------
# Generate fresh accounts (random 32-byte keys)
# ---------------------------------------------------------------------------
def new_account(key: LezKey = None) -> tuple[str, LezKey]:
    """Generate a new random Ed25519 keypair. Returns (account_id_b58, key)."""
    raw = secrets.token_bytes(32)
    k = LezKey(raw.hex())
    return k.account_id, k


# ---------------------------------------------------------------------------
# Main deployer
# ---------------------------------------------------------------------------
def deploy_program(elf_path: Path, key: LezKey, payer_id: str, dry_run: bool = False) -> dict:
    """
    Deploy a RISC Zero guest ELF (user_elf portion) to LEZ via program_loader.
    
    Steps:
      1. Split user_elf into 96KB chunks
      2. Upload segments last-to-first (each references the next)
      3. Create header pointing at first segment
    
    Returns dict with program_id, segments, deploy txs.
    """
    print(f"\n{'='*70}")
    print(f"  Deploying: {elf_path.name} ({elf_path.stat().st_size:,} bytes)")
    print(f"  Payer: {payer_id}")
    print(f"{'='*70}")

    user_elf = elf_path.read_bytes()
    print(f"  ELF size: {len(user_elf):,} bytes")

    # Split into chunks
    chunks = []
    for i in range(0, len(user_elf), MAX_SEGMENT_DATA_LEN):
        chunks.append(user_elf[i:i + MAX_SEGMENT_DATA_LEN])
    n_segments = len(chunks)
    print(f"  Segments : {n_segments} chunks of max {MAX_SEGMENT_DATA_LEN:,} bytes")

    if n_segments > 16:  # MAX_PROGRAM_SEGMENTS
        raise ValueError(f"Too many segments: {n_segments} > 16 max")

    # Generate segment account keypairs
    seg_keys = [new_account() for _ in range(n_segments)]
    seg_ids = [ak[0] for ak in seg_keys]  # base58 account IDs

    # Generate header account keypair
    header_id, header_key = new_account()

    print(f"  Header   : {header_id}")
    for i, sid in enumerate(seg_ids):
        print(f"  Segment{i:2d}: {sid}")

    if dry_run:
        print("\n  [DRY RUN] Not sending transactions.")
        return {"program_id": header_id, "segments": seg_ids, "dry_run": True}

    # Get fee state once
    fee_state = get_fee_state()
    print(f"\n  Fee state: exec={fee_state['base_fee_exec']}, stor={fee_state['base_fee_stor']}, block={fee_state['height']}")

    sent_txs = []

    # Upload segments last-to-first
    for i in range(n_segments - 1, -1, -1):
        next_seg = seg_ids[i + 1] if i + 1 < n_segments else None
        instruction_data = encode_write_segment(chunks[i], next_seg)
        target_accounts  = [(seg_ids[i], True)]

        print(f"\n  [segment {i}] chunk={len(chunks[i]):,}B  next={next_seg or 'None'}")

        # Retry up to 3 times
        for attempt in range(1, 4):
            # Fresh nonce each attempt
            nonce = get_nonce(payer_id)
            # Refresh fee state
            fee_state = get_fee_state()

            tx_bytes, tx_hash_local = build_program_loader_tx(
                key             = key,
                payer_id        = payer_id,
                instruction_data= instruction_data,
                target_accounts = target_accounts,
                gas_limit       = GAS_WRITE_SEGMENT,
                nonce           = nonce,
                fee_state       = fee_state,
            )
            tx_b58 = b58encode(tx_bytes)

            print(f"    attempt {attempt}: nonce={nonce}, local_hash={tx_hash_local[:16]}...")

            try:
                tx_hash = send_transaction(tx_b58)
                print(f"    sent! hash={tx_hash}")
                block = wait_for_tx(tx_hash, timeout=120)
                if block:
                    print(f"    included in block {block}")
                    sent_txs.append({"kind": f"segment{i}", "tx": tx_hash, "block": block})
                    break
                else:
                    print(f"    not included after 120s, retrying...")
            except Exception as e:
                print(f"    send failed: {e}")
                if attempt == 3:
                    raise

    # Create header
    print(f"\n  [header] first_segment={seg_ids[0]}")
    instruction_data = encode_create_header(seg_ids[0], immutable=False)
    # Header target must be is_authorized — both header key and payer key sign
    target_accounts = [(header_id, True)]

    for attempt in range(1, 4):
        nonce = get_nonce(payer_id)
        fee_state = get_fee_state()

        tx_bytes, tx_hash_local = build_program_loader_tx(
            key             = key,
            payer_id        = payer_id,
            instruction_data= instruction_data,
            target_accounts = target_accounts,
            gas_limit       = GAS_CREATE_HEADER,
            nonce           = nonce,
            fee_state       = fee_state,
        )
        tx_b58 = b58encode(tx_bytes)
        print(f"    attempt {attempt}: nonce={nonce}, local_hash={tx_hash_local[:16]}...")

        try:
            tx_hash = send_transaction(tx_b58)
            print(f"    sent! hash={tx_hash}")
            block = wait_for_tx(tx_hash, timeout=120)
            if block:
                print(f"    included in block {block} ✓")
                sent_txs.append({"kind": "header", "tx": tx_hash, "block": block})
                break
            else:
                print(f"    not included after 120s, retrying...")
        except Exception as e:
            print(f"    send failed: {e}")
            if attempt == 3:
                raise

    return {
        "program_id": header_id,
        "segments"  : seg_ids,
        "txs"       : sent_txs,
        "image_id"  : "pending",  # computed by LEZ at header creation
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="LEZ v0.3.1 Pure-Python Program Deployer (Mosoo)")
    parser.add_argument("--elf", help="Path to user ELF binary (or packed .bin)")
    parser.add_argument("--check-balance", action="store_true", help="Check payer balance and exit")
    parser.add_argument("--dry-run", action="store_true", help="Validate only, don't send txs")
    parser.add_argument("--check-tx", help="Check if a tx hash is included")
    parser.add_argument("--decode-tx", help="Decode and show a live transaction by hash")
    args = parser.parse_args()

    wallet = json.loads(WALLET_JSON.read_text())
    payer_id = wallet["accountId"]
    key = LezKey(wallet["privateKeyHex"])

    # Verify key matches wallet
    assert key.account_id == payer_id, f"Key mismatch: {key.account_id} != {payer_id}"
    print(f"  Payer account: {payer_id}")

    if args.check_balance:
        balance = get_balance(payer_id)
        fee_state = get_fee_state()
        nonce = get_nonce(payer_id)
        print(f"  Balance      : {balance:,} lepta ({balance / 1e6:.4f} LEZ)")
        print(f"  Nonce        : {nonce}")
        print(f"  Block height : {fee_state['height']}")
        print(f"  Base fee exec: {fee_state['base_fee_exec']}")
        return

    if args.check_tx:
        r = rpc("getTransaction", [args.check_tx])
        print(json.dumps(r, indent=2))
        return

    if args.decode_tx:
        r = rpc("getTransaction", [args.decode_tx])
        if r.get("result"):
            raw_b64, block = r["result"]
            raw = base64.b64decode(raw_b64)
            print(f"  Block  : {block}")
            print(f"  Bytes  : {len(raw)}")
            print(f"  Tag    : {raw[0]} ({'Public' if raw[0]==0 else 'PrivacyPreserving'})")
            print(f"  Hex(64): {raw[:64].hex()}")
        else:
            print("  Not found")
        return

    if not args.elf:
        parser.print_help()
        sys.exit(1)

    elf_path = Path(args.elf)
    if not elf_path.exists():
        print(f"[ERROR] ELF not found: {elf_path}")
        sys.exit(1)

    # Pre-flight
    balance = get_balance(payer_id)
    fee_state = get_fee_state()
    print(f"  Balance: {balance:,} lepta ({balance/1e6:.4f} LEZ)")
    print(f"  Block  : {fee_state['height']}")

    if balance < 1_000_000 and not args.dry_run:
        print("[ERROR] Insufficient balance")
        sys.exit(1)

    result = deploy_program(elf_path, key, payer_id, dry_run=args.dry_run)

    # Save results
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EVIDENCE_DIR / "deploy.json"
    out_file.write_text(json.dumps(result, indent=2))
    print(f"\n  Results saved to: {out_file}")
    print(f"  Program ID: {result['program_id']}")

    # Write TSV header
    tsv_file = EVIDENCE_DIR / "run.tsv"
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# mosoo_lc run (testnet) against {RPC_URL}, {ts}",
        f"# program {result['program_id']} {result.get('image_id','pending')}",
        f"# payer {payer_id} instance mainnet-v031",
    ]
    for tx_info in result.get("txs", []):
        lines.append(f"# deploy {tx_info['kind']} {tx_info['tx']}")
    tsv_file.write_text("\n".join(lines) + "\n")
    print(f"  Manifest   : {tsv_file}")


if __name__ == "__main__":
    main()
