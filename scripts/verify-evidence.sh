#!/usr/bin/env bash
# Verifies the Mosoo sequencer harness execution evidence manifest.
#
# Usage:
#   scripts/verify-evidence.sh
#   scripts/verify-evidence.sh --manifest evidence/sequencer-harness-v04/run.tsv
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFEST="${REPO_ROOT}/evidence/sequencer-harness-v04/run.tsv"

if [ "${1:-}" == "--manifest" ] && [ -n "${2:-}" ]; then
    MANIFEST="$2"
fi

if [ ! -f "${MANIFEST}" ]; then
    echo "[!] Error: Manifest not found at ${MANIFEST}" >&2
    exit 1
fi

python3 "${SCRIPT_DIR}/verify-evidence.py" --manifest "${MANIFEST}"
