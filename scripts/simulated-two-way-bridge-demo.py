#!/usr/bin/env python3
"""
Mosoo Simulated Two-Way Bridge Demo
Provides an in-memory, reproducible simulation walkthrough of the full 5-phase cross-chain bridge lifecycle:
1. Ethereum Vault Deposit (MosooLocker.sol)
2. LEZ Consensus Sync & MPT Proof Attestation
3. Minting synthetic mETH & Intra-LEZ Transfer
4. Burning mETH on LEZ
5. Unlocking native ETH on Ethereum with Replay and Guardian-Cancellation Defense

Usage:
    python scripts/simulated-two-way-bridge-demo.py
"""

import sys
import subprocess

if __name__ == "__main__":
    # Delegates to the unified pipeline runner in simulated mode
    cmd = [sys.executable, "scripts/testnet-two-way-bridge.py", "--mode", "simulated"]
    sys.exit(subprocess.call(cmd))
