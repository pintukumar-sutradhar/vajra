#!/usr/bin/env bash
# VAJRA — one-shot setup: installs everything, starts the platform in the
# background, and tells you which port the UI is on.
#
#   ./setup.sh          full first-time install + start in the background
#
# After setup, use `vajra` to show the port/status again and `vajra --stop`
# to stop it. Run this from the repository root.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f vajra-launcher ]; then
    echo "setup.sh must be run from the VAJRA repository root" >&2
    exit 1
fi

exec python3 vajra-launcher --setup "$@"