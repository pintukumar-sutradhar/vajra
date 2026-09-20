#!/usr/bin/env bash
# VAJRA restore — replace the platform state from a backup archive.
#
#   ./scripts/restore.sh backups/vajra-YYYYMMDD_HHMMSS.tar.gz
#
# WARNING: stop the API and worker processes first. Restoring while they run
# will clobber data underneath a live writer.

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

ARCHIVE="${1:?usage: ./scripts/restore.sh <backup.tar.gz>}"
[ -f "$ARCHIVE" ] || { echo "no such archive: $ARCHIVE"; exit 1; }

VAR="${VAJRA_PLATFORM_VAR:-$ROOT/server/var}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$ARCHIVE" -C "$STAGE"

[ -f "$STAGE"/*/platform.db ] \
  || { echo "archive does not contain a platform.db — refusing to restore"; exit 1; }

mkdir -p "$VAR"
echo "Restoring into: $VAR"
echo "  ensure services are STOPPED before continuing."
read -r -p "Continue? [y/N] " ans
case "$ans" in [yY]*) ;; *) echo "aborted"; exit 1 ;; esac

cp -a "$STAGE"/*/platform.db "$VAR/platform.db"
chmod 600 "$VAR/platform.db"
if [ -d "$STAGE"/*/runs ]; then cp -a "$STAGE"/*/runs "$VAR/runs"; fi
if [ -f "$STAGE"/*/secret.key ]; then
  cp -a "$STAGE"/*/secret.key "$VAR/secret.key"
  chmod 600 "$VAR/secret.key"
fi

echo "Restore complete. Start the API + worker and verify the first login."