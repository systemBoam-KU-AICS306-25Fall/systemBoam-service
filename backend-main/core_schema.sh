#!/usr/bin/env bash
set -euo pipefail

# Paths
BACKEND_DIR="${BACKEND_DIR:-$HOME/systemBoam-service/backend-main}"
VENV_DIR="${VENV_DIR:-$HOME/systemBoam-service/.venv}"

# Force master credentials for this script
export DB_USER="boammaster"
export DB_PASSWORD="dbmaster"

# Sanity checks
[ -f "$VENV_DIR/bin/activate" ] || { echo "Missing venv: $VENV_DIR" >&2; exit 1; }
[ -d "$BACKEND_DIR" ] || { echo "Missing backend: $BACKEND_DIR" >&2; exit 1; }

# Activate venv and cd into backend
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
cd "$BACKEND_DIR"

# Grant DB/schema privileges and broad table/sequence grants (no %I format)
python3 - <<'PY'
from sqlalchemy import text
from app.db import engine

sql = """
-- Ensure DB-level privileges so appuser can create objects
GRANT CONNECT ON DATABASE collectdb TO appuser;
GRANT CREATE  ON DATABASE collectdb TO appuser;

-- Ensure schema 'core' exists (owned by current role: master)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'core') THEN
        EXECUTE 'CREATE SCHEMA core';
    END IF;
END $$;

-- Allow appuser to use and create objects in 'core'
GRANT USAGE  ON SCHEMA core TO appuser;
GRANT CREATE ON SCHEMA core TO appuser;

-- Existing objects: grant broad privileges to appuser
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON ALL TABLES IN SCHEMA core TO appuser;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core TO appuser;

-- Future objects: default privileges so new tables/sequences are usable by appuser
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES   TO appuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT USAGE,  SELECT, UPDATE           ON SEQUENCES TO appuser;
"""
with engine.begin() as conn:
    conn.exec_driver_sql(sql)

print("OK: schema/core grants applied to appuser")
PY
