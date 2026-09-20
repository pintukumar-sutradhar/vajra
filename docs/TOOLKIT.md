# VAJRA Toolkit

Build/ops utilities under `tools/` — stdlib only, runnable outside the
framework (each is a normal CLI script with `-h`). Everything here is
read-only or regenerates shipped data; nothing executes attacker-supplied
payloads.

## tools/_core.py

Shared helpers (colors, JSON loading, project-root discovery). Imported by the
other tools; not a CLI itself.

## tools/wordlists.py — wordlist ops

```
wordlists.py list                  # catalog what ships
wordlists.py info passwords        # stats on a shipped or absolute list
wordlists.py filter -i dirs.txt -o small.txt -l 4-12 -r '^[a-z]'
wordlists.py merge -i users -i more -o all.txt     # unique lines
```

Inspects/filters/merges the framework wordlists. Also provides the `SHIPPED`
manifest used by `core/selftest.py` to verify the shipped wordlists.
`core/selftest.py` imports `from tools.wordlists import SHIPPED`.

## tools/gen_wordlists.py — deterministic list generator

```
python3 tools/gen_wordlists.py     # builds wordlists/*.txt from rules
```

Regenerates the shipped `wordlists/*.txt` (users / passwords / dirs / subs)
from deterministic rules so the payload sets stay auditable.

## tools/build_cve_db.py — CVE knowledge base builder

```
python tools/build_cve_db.py /path/to/advisory-database-main.tar.gz
```

Rebuilds `intel/cve_db.json` from the GitHub advisory-database archive. The
shipped `intel/cve_db.json` is the offline source the engine's banner→CVE
correlation uses.

## tools/build_coverage_bank.py — detection-coverage bank builder

```
python tools/build_coverage_bank.py
```

Surface/under-test inventory of the engine's detection modules. Regenerates
the coverage bank referenced by selftest; keeps the detection matrix honest.

## layout

```
tools/
  _core.py           shared helpers
  wordlists.py       inspect/filter/merge wordlists + SHIPPED manifest
  gen_wordlists.py   deterministic list generator (framework)
  build_cve_db.py    intel/cve_db.json builder (offline CVE knowledge base)
  build_coverage_bank.py   detection-coverage inventory builder
```