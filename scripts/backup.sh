#!/usr/bin/env bash
# VAJRA backup — consistent snapshot of the platform database, scan runs and
# secrets into a single dated archive.
#
#   ./scripts/backup.sh [dest-dir]     # default: ./backups
#
# The SQLite backup uses sqlite3's online backup API, so a running platform
# is fine (the API and worker keep going during the copy).
#
# For Postgres instead: `pg_dump "postgresql://user:pass@host/vajra" -Fc \
#   -f "$DEST/vajra.dump"`.

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

VAR="${VAJRA_PLATFORM_VAR:-$ROOT/server/var}"
DEST="${1:-$ROOT/backups}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$DEST/vajra-$STAMP"
mkdir -p "$OUT"

if [ -f "$VAR/platform.db" ]; then
  python3 - "$VAR/platform.db" "$OUT/platform.db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
c, o = sqlite3.connect(src), sqlite3.connect(dst)
with o:
    c.backup(o)
o.close(); c.close()
PY
  chmod 600 "$OUT/platform.db"
  echo "  db: $OUT/platform.db"
else
  echo "  (!) no platform.db in $VAR — skipping database"
fi

if [ -d "$VAR/runs" ]; then
  cp -a "$VAR/runs" "$OUT/runs"
  echo "  runs: $OUT/runs"
fi
if [ -f "$VAR/secret.key" ]; then
  cp -a "$VAR/secret.key" "$OUT/secret.key"
  chmod 600 "$OUT/secret.key"
  echo "  secret.key: $OUT/secret.key"
fi

tar -czf "$OUT.tar.gz" -C "$DEST" "$(basename "$OUT")" && rm -rf "$OUT"
echo
echo "Backup written: $OUT.tar.gz"
echo "(keep the archive and its decryption method somewhere separate from this host)"