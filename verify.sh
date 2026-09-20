#!/usr/bin/env bash
# VAJRA — one-shot integrity check.
#
# Runs every gate that guards detection quality, in the order that fails
# fastest. Run this after any change to core/, modules/ or server/; the exit
# code is non-zero if anything is wrong.
#
#   ./verify.sh          # everything
#   ./verify.sh --quick  # syntax + proof gate only (no network fixtures)
#
# Authorized use only. The fixtures this starts are local (127.0.0.1) and
# deliberately vulnerable; they are never exposed off-host.
set -uo pipefail

cd "$(dirname "$0")" || exit 1
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

FAILED=0
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
pass() { printf '\033[92m  PASS\033[0m %s\n' "$1"; }
fail() { printf '\033[91m  FAIL\033[0m %s\n' "$1"; FAILED=1; }

step "Python syntax (engine, modules, platform)"
# Parse-only, via ast: `py_compile` writes bytecode, and a __pycache__ left
# behind by a root-owned setup run turns that into "Permission denied" — which
# looks exactly like a syntax error and is not one. Parsing touches no disk.
PY_FILES=$(find . -name '*.py' \
  -not -path './.venv/*' -not -path './webapp/*' \
  -not -path '*/__pycache__/*' -not -path './Outputs/*')
if "$PY" -c '
import ast, sys
bad = []
for f in sys.argv[1:]:
    try:
        ast.parse(open(f, encoding="utf-8", errors="replace").read(), f)
    except SyntaxError as e:
        bad.append("%s:%s: %s" % (f, e.lineno, e.msg))
for line in bad:
    print("    " + line)
sys.exit(1 if bad else 0)
' $PY_FILES; then
  pass "$(echo "$PY_FILES" | wc -l) files parse cleanly"
else
  fail "syntax errors above"
fi

step "Proof gate completeness"
# Exit status is the gate: 0 only when no module files a finding behind the
# gate's back and every class it uses has a rule.
if "$PY" core/proof_audit.py; then
  pass "no bypasses, every class has a rule"
else
  fail "modules still bypass the gate (run: $PY core/proof_audit.py --list)"
fi

if [ "$QUICK" = "1" ]; then
  step "Skipping fixtures/tests (--quick)"
else
  step "Engine self-test"
  "$PY" vajra.py --selftest || fail "engine self-test reported failures"

  step "Detection-integrity tests (hostile fixtures)"
  # Starts local fixtures on 8910-8914 and asserts: zero findings against four
  # soft-404/wildcard hosts, the real issues against the vulnerable one, no XSS
  # on an HTML-escaping parameter, and proof/evidence unit behaviour.
  "$PY" tests/run.py || fail "detection-integrity tests failed"

  step "Platform API tests"
  # Isolated temp database; exercises auth, lockout, user management, roles,
  # password rotation, API keys, CSV export and the audit trail over the real
  # HTTP surface (in-process, no ports bound).
  "$PY" tests/platform_e2e.py || fail "platform API tests failed"
fi

step "Webapp build"
if [ -d webapp/node_modules ]; then
  ( cd webapp && npm run build >/tmp/vajra_web.log 2>&1 ) \
    && pass "vite build succeeded" \
    || { fail "webapp build failed:"; tail -25 /tmp/vajra_web.log | sed 's/^/    /'; }
else
  printf '\033[93m  SKIP\033[0m webapp/node_modules missing — run ./setup.sh\n'
fi

step "Result"
if [ "$FAILED" = "0" ]; then
  printf '\033[92mAll checks passed.\033[0m\n'
else
  printf '\033[91mOne or more checks failed — see above.\033[0m\n'
fi
exit "$FAILED"
