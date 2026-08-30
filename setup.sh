#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "[*] VAJRA installer"
if [[ "${1:-}" == "--system" ]]; then
    echo "[*] installing optional deps system-wide"
    pip3 install --break-system-packages -r requirements.txt || \
        pip3 install -r requirements.txt || echo "[!] some extras failed - VAJRA still works on stdlib"
else
    if [[ ! -d .venv ]]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install -q --upgrade pip || true
    pip install -q -r requirements.txt || echo "[!] extras failed - stdlib fallback active"
fi

chmod +x vajra.py
if [[ ! -f wordlists/passwords_full.txt ]]; then
    echo "[*] forging deep wordlists (~265k entries)"
    if [[ -d .venv ]]; then
        .venv/bin/python tools/gen_wordlists.py
    else
        python3 tools/gen_wordlists.py
    fi
fi
if [[ -d .venv ]]; then
    .venv/bin/python vajra.py --selftest
else
    python3 vajra.py --selftest
fi

if [[ -w /usr/local/bin ]]; then
    ln -sf "$(pwd)/vajra.py" /usr/local/bin/vajra
    echo "[*] symlinked -> vajra (global command)"
fi

echo ""
echo "[+] Done. Run:"
echo "      python3 vajra.py -t <ip-or-url> --profile full --yes"
echo "    or (after symlink):  vajra -t <target> --yes"
