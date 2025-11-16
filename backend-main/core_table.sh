#!/usr/bin/env bash
set -euo pipefail

# Paths
BACKEND_DIR="${BACKEND_DIR:-$HOME/systemBoam-service/backend-main}"
VENV_DIR="${VENV_DIR:-$HOME/systemBoam-service/.venv}"

# Optional: force app credentials if your env differs
# export DB_USER="appuser"
# export DB_PASSWORD="hmsjeremiah"

[ -f "$VENV_DIR/bin/activate" ] || { echo "Missing venv: $VENV_DIR" >&2; exit 1; }
[ -d "$BACKEND_DIR" ] || { echo "Missing backend: $BACKEND_DIR" >&2; exit 1; }

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
cd "$BACKEND_DIR"

python3 - <<'PY'
from sqlalchemy import text
from app.db import engine

ddl = """
-- Create base table first to avoid FK permission issues
CREATE TABLE IF NOT EXISTS core.cves (
  cve_id           text PRIMARY KEY,
  summary          text,
  published        timestamptz,
  last_modified    timestamptz,
  state            text DEFAULT 'PUBLISHED',
  cvss_v31_score   numeric
);

-- Other tables referencing core.cves
CREATE TABLE IF NOT EXISTS core.news_articles (
  id           bigserial PRIMARY KEY,
  published_at timestamptz NOT NULL,
  title        text NOT NULL,
  url          text NOT NULL,
  cve_ids      text[] DEFAULT '{}',
  score        numeric,
  created_at   timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS core.epss (
  cve_id     text PRIMARY KEY REFERENCES core.cves(cve_id) ON DELETE CASCADE,
  epss       numeric,
  percentile numeric,
  as_of      date
);

CREATE TABLE IF NOT EXISTS core.kve (
  cve_id    text PRIMARY KEY REFERENCES core.cves(cve_id) ON DELETE CASCADE,
  kve_score numeric
);

CREATE TABLE IF NOT EXISTS core.kev (
  cve_id     text PRIMARY KEY REFERENCES core.cves(cve_id) ON DELETE CASCADE,
  kev_flag   boolean DEFAULT true,
  first_seen date
);

CREATE TABLE IF NOT EXISTS core.activity (
  cve_id         text   NOT NULL REFERENCES core.cves(cve_id) ON DELETE CASCADE,
  time_window    text   NOT NULL,
  activity_score numeric,
  last_seen      timestamptz,
  PRIMARY KEY (cve_id, time_window)
);

-- Minimal indexes (those not depending on existing owner)
CREATE INDEX IF NOT EXISTS idx_news_articles_published
  ON core.news_articles (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_window
  ON core.activity (cve_id, time_window);
"""
with engine.begin() as conn:
    conn.exec_driver_sql(ddl)

print("OK: core tables/indexes created by appuser")
PY
