#!/usr/bin/env bash
# One-command launcher for TriageDesk.
#   ./run.sh                    # seed 60 alerts, serve on http://localhost:8000
#   TD_SEED_COUNT=100 ./run.sh  # more starting alerts
#   TD_ONLINE=1 ./run.sh        # enable live ip-api enrichment (no key needed)
set -euo pipefail
cd "$(dirname "$0")"
echo "[*] Installing dependencies (first run only)..."
python3 -m pip install -q -r requirements.txt --break-system-packages 2>/dev/null || \
  python3 -m pip install -q -r requirements.txt
echo "[*] Starting TriageDesk on http://localhost:8000"
exec python3 -m uvicorn web.app:app --host 0.0.0.0 --port 8000
