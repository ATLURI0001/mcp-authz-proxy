#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/setup-demo.py
docker compose up --build -d
python3 scripts/smoke.py
