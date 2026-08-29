"""VAJRA GraphQL surface prober — introspection, playgrounds, schema leak."""
import json

from core.database import Finding

CANDIDATES = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql",
              "/v2/graphql", "/graphql/console", "/explorer", "/altair",
              "/query", "/gql"]

INTROSPECTION = ('{"query":"{ __schema { queryType { name } types { name } } }"}')


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    checked = 0
    for wt in targets[:2]:
        base = wt["url"].rstrip("/")
        for path in CANDIDATES:
            url = base + path
            r0 = engine.http.get(url, allow_redirects=False)
            if r0.status in (404, 0):
                continue
            checked += 1
            marker = None
            r = engine.http.post(url, data=INTROSPECTION,
                                 headers={"Content-Type": "application/json"},
                                 allow_redirects=False)
            body = r.body or ""
            try:
                j = r.json
            except Exception:
                j = None
            if isinstance(j, dict) and "__schema" in json.dumps(j)[:4000]:
                marker = "introspection enabled"
            elif "graphiql" in body.lower() or "apollo" in body.lower() \
                    or "playground" in body.lower():
                marker = "interactive IDE exposed"
            if marker:
                sev = "medium" if marker.startswith("introspection") else "low"
                engine.db.add_finding(Finding(
                    t.display, "web.graphql_probe", "exposure", sev,
                    "GraphQL endpoint exposed at %s (%s)" % (path, marker),
                    detail="Introspection reveals the complete API schema "
                           "(types, mutations, hidden fields) — a map for "
                           "targeted injection and IDOR testing.",
                    evidence="%s -> HTTP %d" % (url, r.status),
                    remediation="Disable introspection in production; add "
                                "depth/complexity limits.",
                    confidence="firm"))
    if checked:
        engine.db.add_finding(Finding(
            t.display, "web.graphql_probe", "recon", "info",
            "GraphQL candidates reachable: %d path(s) checked"
            % checked, confidence="possible"))
