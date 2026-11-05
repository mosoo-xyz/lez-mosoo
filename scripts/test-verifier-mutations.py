#!/usr/bin/env python3
"""
Mosoo Verifier Mutation Test Suite
Simulates 7 deliberate corruptions of the execution manifest (run.tsv)
and verifies that scripts/verify-evidence.py strictly catches all 7 mutations (100% detection rate).
"""

import sys
import os
import subprocess
import tempfile

def run_verifier_on_content(manifest_content: str) -> tuple[int, str, str]:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    verifier_script = os.path.join(repo_root, "scripts", "verify-evidence.py")
    
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tsv", delete=False) as tmp:
        tmp.write(manifest_content)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [sys.executable, verifier_script, "--manifest", tmp_path],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    canonical_manifest = os.path.join(repo_root, "evidence", "sequencer-harness-v04", "run.tsv")

    with open(canonical_manifest, "r", encoding="utf-8") as f:
        canonical_content = f.read()

    print("=" * 80)
    print("Mosoo Verifier Mutation Testing Suite (RFP-021 Evidence Integrity)")
    print("Verifying that the evidence verifier rejects 7 deliberate manifest corruptions")
    print("=" * 80)

    # Base test: Canonical manifest MUST PASS
    ret, out, err = run_verifier_on_content(canonical_content)
    if ret != 0:
        print("[!] ERROR: Canonical manifest failed verification!", file=sys.stderr)
        print(err, file=sys.stderr)
        sys.exit(1)
    print("[+] Baseline Verification: Canonical run.tsv passed with 0 errors.\n")

    mutations = [
        (
            "Mutation 1: Fake Transaction Hash",
            canonical_content.replace(
                "0xfb524c5c5c61a32c74a125f85f6b93f15b2f3b443be345ab37e6ad2d4785fc6c",
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            ),
            "NOT verified in test output"
        ),
        (
            "Mutation 2: Refused -> Applied Flip (Tampered Verdict)",
            canonical_content.replace("replay_erc20_claim\trefused\tAlreadyClaimed", "replay_erc20_claim\tapplied\tapplied"),
            "Unknown or unauthorized transaction action label"
        ),
        (
            "Mutation 3: Applied -> Refused Flip",
            canonical_content.replace("initialize\tapplied\tapplied", "initialize\trefused\tAlreadyClaimed"),
            "NOT confirmed"
        ),
        (
            "Mutation 4: Gas Limit Cap Violation (> 10,000,000 gas)",
            canonical_content.replace("5380000", "15380000"),
            "exceeded 10M gas cap"
        ),
        (
            "Mutation 5: Unknown Action Label Injection",
            canonical_content.replace("attest_state", "unauthorized_backdoor_action"),
            "Unknown or unauthorized transaction action label"
        ),
        (
            "Mutation 6: Tampered Adversarial Rejection Reason",
            canonical_content.replace("HeaderNotFinalized", "FabricatedSignatureAccepted"),
            "NOT confirmed"
        ),
        (
            "Mutation 7: Non-Existent Execution Proof Hash",
            canonical_content.replace(
                "0x1626ff854cdbb1b3255d45fbff15c07b1ab35df672816992fa3beed40dc3aa11",
                "0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
            ),
            "NOT verified in test output"
        ),
    ]

    caught = 0
    for idx, (label, mutated_content, expected_err_substring) in enumerate(mutations, 1):
        code, m_out, m_err = run_verifier_on_content(mutated_content)
        combined = m_out + "\n" + m_err
        if code != 0 and expected_err_substring.lower() in combined.lower():
            print(f"  ok   [{idx}/7] {label:<50} -> CAUGHT (Verifier exited {code})")
            caught += 1
        else:
            print(f"  [FAIL] [{idx}/7] {label:<50} -> NOT CAUGHT! (Code: {code})", file=sys.stderr)

    print("\n" + "=" * 80)
    print(f"[+] Mutation Test Result: {caught} / {len(mutations)} deliberate corruptions caught by verifier.")
    if caught == len(mutations):
        print("[+] Status: PASS (100% Tamper Detection Rate)")
        print("=" * 80)
        sys.exit(0)
    else:
        print("[!] Status: FAIL (Some mutations evaded verification)", file=sys.stderr)
        print("=" * 80)
        sys.exit(1)

if __name__ == "__main__":
    main()
