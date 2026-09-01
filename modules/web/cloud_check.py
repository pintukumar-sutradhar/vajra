"""VAJRA cloud exposure (web.cloud) — read-only discovery and listing of
publicly-exposed S3 / Google Cloud Storage / Azure Blob storage buckets
derived from the target's domain, subdomains and crawled pages.

Only HTTP(S) fetch is used — no credentials, no write access, mirrors what
a scanner + curl would see."""
import re
from urllib.parse import urlparse

from core.database import Finding

LIST_MARKERS = (b"<ListBucketResult", b"<Contents>", b"<Key>", b"<Blobs>",
                b"NextMarker", b"<NextContinuationToken")
BUCKET_RE = re.compile(r"https?://([a-z0-9][a-z0-9.\-]{2,63})\.s3\.amazonaws\.com",
                       re.I)
AZURE_BLOB_RE = re.compile(r"https?://([a-z0-9][a-z0-9\-]{2,62})\.blob\.core\.windows\.net",
                           re.I)
GCS_URI_RE = re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{2,221})/?")


def _hostnames(engine):
    names = set()
    t = engine.target
    host = (t.hostname or "").strip()
    if host and host.count(".") >= 1:
        names.add(host)
        names.add(host.split(":")[0])
    for w in engine.state.get("web_targets", []) or []:
        try:
            h = urlparse(w["url"]).hostname or ""
        except Exception:
            h = ""
        if h:
            names.add(h)
    for sub in engine.state.get("subdomains", []) or []:
        if isinstance(sub, dict):
            h = sub.get("host") or sub.get("name") or sub.get("subdomain") or ""
        else:
            h = sub
        if h:
            names.add(h)
    return {n.lower().rstrip(".") for n in names if n}


def _clean(name):
    n = name.strip().lower().replace("_", "-")
    n = re.sub(r"^www\.|^app\.|^api\.|^dev\.|^staging\.|^test\.", "", n)
    return n


def bucket_candidates(engine):
    cands = []
    seen = set()
    for h in sorted(_hostnames(engine)):
        cleaned = _clean(h)
        for base in {h, cleaned}:
            base = base.strip(".")
            label = base.split(".")[0] if "." in base else base
            for x in (base, label):
                x = x.strip("-.")
                if x and x not in seen and len(x) >= 3 and not x.isdigit():
                    seen.add(x)
                    cands.append(x)
    # grow a few vendor-suffix variants on the shortest names
    extras = []
    for c in list(cands)[:int(engine.cfg("bucket_candidates", 30))]:
        for suf in ("-backup", "-prod", "-logs", "-uploads", "-data"):
            x = c + suf
            if x not in seen:
                seen.add(x)
                extras.append(x)
    return (cands + extras)[:int(engine.cfg("bucket_candidates", 30))]


def _is_listing(body):
    return any(m in body for m in LIST_MARKERS)


def _probe(engine, url):
    try:
        r = engine.http.get(url, allow_redirects=False,
                            timeout=min(6, engine.http.timeout))
        return r
    except Exception:
        return None


def run(engine):
    t = engine.target
    cands = bucket_candidates(engine)
    if not cands:
        engine.db.add_event(t.display, "web.cloud",
                            "no domain-derived bucket candidates")
        return
    strong = {h.lower().rstrip(".") for h in _hostnames(engine)}
    engine.log.info("[cloud] probing %d bucket-candidate name(s)" % len(cands))
    public, exists, missing = [], [], []
    checks_done = 0
    cap = int(engine.cfg("bucket_max_checks", 30))
    for name in cands:
        if checks_done >= cap:
            break
        targets_urls = {
            "s3": ["https://%s.s3.amazonaws.com/" % name,
                   "https://s3.amazonaws.com/%s/" % name],
            "gcs": ["https://storage.googleapis.com/%s/" % name],
            "azure": ["https://%s.blob.core.windows.net/?comp=list" % name],
        }
        for prov, urls in targets_urls.items():
            for url in urls:
                checks_done += 1
                r = _probe(engine, url)
                if r is None:
                    continue
                if r.status == 200 and _is_listing(r.content):
                    public.append((prov, name, url))
                    break
                if r.status == 200:
                    exists.append((prov, name, "public-200", url))
                    break
                if r.status in (403, 401):
                    region = r.headers.get("x-amz-bucket-region", "").lower()
                    exists.append((prov, name,
                                   "denied%s" % (" region=" + region
                                                 if region else ""), url))
                    break
                if r.status in (404, 410):
                    missing.append((prov, name))
                    break
        if checks_done >= cap:
            break
    for prov, name, url in public:
        engine.db.add_finding(Finding(
            t.display, "web.cloud", "verified-exposure", "critical",
            "PUBLIC CLOUD BUCKET — LISTING: %s (%s)" % (name, prov.upper()),
            detail="Anonymous HTTP read returned a full object listing at "
                   "%s. Any write-acl extent must be verified and closed." % url,
            evidence="probe=%s\nlisting-returned" % url,
            remediation="Block anonymous access, enable bucket policy "
                        "inspection, enforce encryption/versioning.",
            confidence="certain"))
        engine.log.finding("[cloud] PUBLIC LISTABLE bucket: %s [%s]"
                           % (name, prov.upper()))
    locked = [(p, n, s, u) for p, n, s, u in exists
              if n in strong and s.startswith("denied")]
    if locked:
        engine.db.add_finding(Finding(
            t.display, "web.cloud", "exposure", "info",
            "Cloud storage bucket resolves but is locked — exact subdomain "
            "candidate: %s (%s)" % (locked[0][1], locked[0][0].upper()),
            detail="The bucket for a discovered in-scope subdomain resolves "
                   "and denies anonymous reads. NOT an exposure by itself — "
                   "the lock is the expected secure state.",
            evidence="probe=%s\n-> %s" % (locked[0][0], locked[0][3]),
            confidence="possible"))
    for prov, name, _status, url in exists:
        engine.db.add_event(t.display, "web.cloud",
                            "bucket-name %s/%s resolves (%s)" %
                            (prov, name, url))
    if missing:
        engine.db.add_event(t.display, "web.cloud",
                            "%d candidates nonexistent" % len(missing))
    if public:
        engine.state.setdefault("cloud_buckets", []).extend(
            [p[1] for p in public])
        engine.state.setdefault("cloud_bucket_urls", []).extend(
            [u for _p, _n, u in public if not u.endswith("/?comp=list")])
        engine.state.setdefault("cloud_bucket_urls", []).extend(
            [u for _p, _n, u in public if _p == "azure"])