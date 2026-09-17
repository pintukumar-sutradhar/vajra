# Filing a finding — the proof gate

`engine.record(...)` is the only supported way for a module to report a
vulnerability. Direct `engine.db.add_finding(...)` calls are counted by
`core/proof_audit.py` and fail `vajra.py --selftest`.

The reason is simple: under the old API a module *declared* how confident it
was, and nothing checked the claim. 146 of ~250 call sites declared `firm`,
which the severity ladder lets rise to **high**. A 200 response was enough.
Under this API a module supplies **what it observed**, and the gate decides
both whether the finding exists at all and how confident it may be.

```python
engine.record(target, module, category, severity, title,
              detail="", evidence="", remediation="",
              cls="<class>", proof=P.<kind>(artifact, ...))
```

* `cls` — the vulnerability class, from the table below. It selects the rule.
* `proof` — the artifact that demonstrates it.
* `confidence` is **not** a parameter. It is derived from the proof kind.
* `severity` is still yours, but the proof kind caps it: `marker`,
  `extraction`, `callback` and `auth` reach `critical`; `differential` and
  `observation` stop at `high`.

Outcomes: the proof validates → the finding is written. It does not → the
candidate goes to the suppressed ledger with the reason, and never appears in
findings, reports or dashboards. An unknown `cls` is logged as an **error**,
because that is a gap in the engine rather than a bad module.

## Proof kinds

| Constructor | Use when | Confidence | Cap |
|---|---|---|---|
| `P.marker(artifact)` | a format marker only the real thing produces | certain | critical |
| `P.extraction(artifact)` | a value the target computed (`7*7` → `49`) | certain | critical |
| `P.callback(artifact)` | the target connected back to us | certain | critical |
| `P.auth(artifact)` | we obtained a session or privilege we did not have | certain | critical |
| `P.differential(artifact, control_clean=…, reproduced=…)` | behaviour changed vs a clean control | firm | high |
| `P.observation(artifact)` | a deterministic fact: header absent, port open | firm | high |

Helpers that build the right kind *and* run the checks for the common cases:

```python
P.xss_proof(body, payload, control_body=ctl)   # requires unescaped + executable context
P.lfi_proof(body, control_body=ctl)            # plain or base64 php://filter
P.rce_proof(body, control_body=ctl)            # output of the command actually sent
P.sqli_proof(body, control_body=ctl)           # DB error signature
P.ssti_proof(body, expected, control_body=ctl) # computed value
```

`control_body` is **required** for every class whose rule sets
`requires_control` — all the injection classes. Pass the response body for the
*same parameter with a benign value*. `None` means "no control was run", and
that **fails closed**: the finding is suppressed with
`"no negative control was run"`. This is deliberate. Treating "no control" as
"control came back clean" is exactly how an unproven claim becomes a finding.

## Choosing a class

Pick the class that names the *mechanism*, not the outcome. If nothing fits,
use `other` — but prefer adding a rule in `core/proof.py` over stretching an
existing one.

| Group | Classes |
|---|---|
| Injection | `lfi` `rce` `xss` `sqli` `sqli_blind` `ssti` `xxe` `ssrf` `open_redirect` `crlf` `header_injection` `nosql` `ldap` `xpath` `hpp` `deserialization` `race` `prototype_pollution` `cache_poison` |
| Credential / access | `default_creds` `weak_creds` `brute_force` `auth_bypass` `auth_logic` `privilege_escalation` `jwt` |
| Disclosure | `exposure` `info_leak` `secrets` `sca` `cve` `webshell` `takeover` `cloud` |
| Config | `misconfiguration` `tls` `header` `cors` `cookie` `policy` `compliance` |
| Network | `network_service` `network_tls` `os_fingerprint` |
| Directory | `ad` `ad_misconfig` |
| Other | `business_logic` `upload` `phishing` `other` |

`core/proof.py:PROOF_RULES` is the authority; each rule carries a `why` string
that is shown to the operator when a candidate is suppressed, so it should read
as an explanation, not a code.

## What "observation" is for

Most non-injection findings are not inference at all — an open port, an absent
`Content-Security-Policy`, a TLS version the server negotiated, an LDAP
attribute that says an account is kerberoastable. Those are deterministic
facts, and `P.observation(artifact)` is correct and honest for them. The
artifact should be the thing observed:

```python
engine.record(t.display, "network.services", "exposure", "medium",
              "SMB signing not required on %s" % host,
              evidence=detail, remediation=REM["smb_signing"],
              cls="network_service",
              proof=P.observation("SMB2 NEGOTIATE response: signing_required=0",
                                  note="server accepted unsigned session setup"))
```

Do **not** reach for `observation` to avoid supplying a control on something
that is genuinely an inference. If the finding says "this input caused that
behaviour", it is a differential and it needs a control.

## Migration rules

1. Change the call, not the detection logic. The condition that decides
   *whether* to report must keep its existing meaning.
2. Where a module has an internal helper (`def record(cls, ...)`) that all its
   sites funnel through, migrate the helper — that is one edit, not twenty.
3. Delete any `confidence=` argument; the gate derives it. Leave `severity`.
4. Delete now-dead confidence ladders (`_confidence_for`, `_poc_gate`) only if
   nothing else uses them.
5. `core/proof_audit.py` must report `0` direct sites when you are done, and
   `vajra.py --selftest` must pass.
