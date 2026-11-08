#!/usr/bin/env python3
"""Generate local-only deployment secrets without overwriting existing secrets."""
from pathlib import Path
import secrets
p=Path(__file__).resolve().parents[1]/'.env'
if p.exists():
    print('.env already exists; preserving it')
else:
    keys=['POSTGRES_PASSWORD','REDIS_PASSWORD','UPSTREAM_ALICE_TOKEN','UPSTREAM_BOB_TOKEN','KEYCLOAK_ADMIN_PASSWORD','GRAFANA_PASSWORD']
    with p.open('x') as f:
        for key in keys: f.write(key+'='+secrets.token_hex(32)+'\n')
    p.chmod(0o600)
    print('Created .env. Demo user passwords are documented in README.md.')
