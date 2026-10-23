#!/usr/bin/env python3
"""
Logos Execution Zone (LEZ) Wallet & Testnet Explorer Tool for Mosoo.
Connects directly to the public LEZ testnet sequencer at https://testnet.lez.logos.co.
"""

import sys
import json
import secrets
import hashlib
import argparse
import urllib.request
import ssl

B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DEFAULT_SEQUENCER = "https://testnet.lez.logos.co"
PINATA_ACCOUNT = "EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7"
FEE_PROGRAM = "2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_CHARS[r])
    for byte in b:
        if byte == 0:
            chars.append(B58_CHARS[0])
        else:
            break
    return "".join(reversed(chars))

def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_CHARS.index(c)
    return n.to_bytes(32, "big")

def rpc_call(url: str, method: str, params: list):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mosoo-LEZ-Client/1.0"}
    )
    with urllib.request.urlopen(req, timeout=10, context=ctx) as res:
        return json.loads(res.read().decode("utf-8"))

def cmd_new(args):
    privkey = secrets.token_bytes(32)
    pubkey = hashlib.sha256(privkey).digest()
    account_id = b58encode(pubkey)
    print("=" * 60)
    print("New LEZ Testnet Account Created (Mosoo Keypair)")
    print("=" * 60)
    print(f"Account ID (Base58) : {account_id}")
    print(f"Public Address      : Public/{account_id}")
    print(f"Private Key (hex)   : {privkey.hex()}")
    print("=" * 60)
    print("Save your private key safely. You can query its balance anytime with:")
    print(f"  py scripts/lez-wallet.py balance {account_id}")

def cmd_balance(args):
    acc = args.account.replace("Public/", "").strip()
    res = rpc_call(args.rpc, "getAccountBalance", [acc])
    if "error" in res:
        print(f"RPC Error querying balance for {acc}: {res['error']}")
        return
    bal = res.get("result", 0)
    print(f"Account: Public/{acc}")
    print(f"Live Testnet Balance: {bal} LEZ")

def cmd_faucet_status(args):
    print("=" * 60)
    print("Logos Execution Zone (LEZ) Public Testnet Faucet Status")
    print(f"Sequencer RPC: {args.rpc}")
    print("=" * 60)
    fee_res = rpc_call(args.rpc, "getFeeState", [])
    if "result" in fee_res:
        f = fee_res["result"]
        print(f"Current Chain Block Height : {f.get('height')}")
        print(f"Base Execution Fee         : {f.get('base_fee_exec')}")
        print(f"Base Storage Fee           : {f.get('base_fee_stor')}")
        print(f"Single-Tx Max Execution Gas: {f.get('max_gas_exec')} (10M Gas Cap)")
    pinata_bal = rpc_call(args.rpc, "getAccountBalance", [PINATA_ACCOUNT])
    bal = pinata_bal.get("result", 0)
    print(f"Piñata Pool Account (Base58): {PINATA_ACCOUNT}")
    print(f"Piñata Pool Balance        : {bal} LEZ")
    if bal == 0:
        print("Status                     : DEPLETED (0 LEZ remaining in community pool)")
        print("Note                       : The Piñata pool was fully claimed by prior testnet runs.")
        print("                             Pre-funded accounts retain active balances for transactions.")
    else:
        print(f"Claims Available           : {bal // 150} (150 LEZ per claim)")

def main():
    parser = argparse.ArgumentParser(description="LEZ Wallet & Testnet Explorer for Mosoo")
    parser.add_argument("--rpc", default=DEFAULT_SEQUENCER, help="Sequencer RPC URL")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # new account
    subparsers.add_parser("new", help="Generate a new LEZ Base58 testnet keypair")

    # balance
    p_bal = subparsers.add_parser("balance", help="Check account balance on live testnet")
    p_bal.add_argument("account", help="Base58 account ID or Public/<id>")

    # faucet
    subparsers.add_parser("faucet-status", help="Check Piñata pool and testnet fee state")

    args = parser.parse_args()
    if args.command == "new":
        cmd_new(args)
    elif args.command == "balance":
        cmd_balance(args)
    elif args.command == "faucet-status":
        cmd_faucet_status(args)

if __name__ == "__main__":
    main()
