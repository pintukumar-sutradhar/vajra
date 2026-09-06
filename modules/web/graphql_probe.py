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
    graphql_confirmed = 0
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
            ct = r.headers.get("content-type", "").lower()
            is_json = "json" in ct
            has_graphql_body = bool(
                j and isinstance(j, dict) and
                "__schema" in json.dumps(j)[:4000])
            if has_graphql_body:
                marker = "introspection enabled"
                graphql_confirmed += 1
            elif is_json and any(k in body.lower() for k in (
                    "graphiql", "apollo", "playground",
                    "__schema", "__type", "graphql")):
                marker = "interactive IDE exposed"
                graphql_confirmed += 1
            if marker:
                sev = "medium" if marker.startswith("introspection") else "low"
                engine.db.add_finding(Finding(
                    t.display, "web.graphql_probe", "exposure", sev,
                    "GraphQL endpoint exposed at %s (%s)" % (path, marker),
                    detail="Introspection reveals the complete API schema "
                           "(types, mutations, hidden fields) — a map for "
                           "targeted injection and IDOR testing.",
                    evidence="%s -> HTTP %d%s" % (
                        url, r.status,
                        ("\n" + json.dumps(j)[:900].replace(" ", ""))
                        if has_graphql_body else ""),
                    remediation="Disable introspection in production; add "
                                "depth/complexity limits.",
                    confidence="firm"))
    if graphql_confirmed:
        engine.db.add_finding(Finding(
            t.display, "web.graphql_probe", "recon", "info",
            "GraphQL confirmed: %d endpoint(s) with GraphQL responses"
            % graphql_confirmed, confidence="firm"))
