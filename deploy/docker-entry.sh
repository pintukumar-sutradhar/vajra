#!/bin/sh
# VAJRA container entrypoint: pick the API or the worker via VAJRA_MODE.
set -e

export VAJRA_PLATFORM_VAR="${VAJRA_PLATFORM_VAR:-/var/lib/vajra}"
mkdir -p "$VAJRA_PLATFORM_VAR/runs"

if [ "$VAJRA_MODE" = "worker" ]; then
  exec python server/run_worker.py
fi
exec python server/run_api.py