"""VAJRA self-update — pulls the latest build from the GitHub upstream.

Auto-detects how the framework was installed:

* git checkout (has an `origin` remote)  -> git fast-forward pull of the
  current branch. Refuses to run when the working tree has local changes or
  when the branch has diverged (nothing is ever clobbered).
* archive install                        -> downloads the GitHub branch
  tarball and replaces the tree in place, preserving `Outputs/` (scan data),
  user data files listed in a skip-set, and `config/config.json` (restored
  from backup). The upstream commit sha is remembered locally so repeat
  checks work without git.

Both paths are non-interactive and offline-safe: any network or git failure
is reported and leaves the installation untouched.
"""
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from core.version import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REPO = "pintukumar-sutradhar/vajra"
DEFAULT_BRANCH = "main"
STATE = os.path.join(ROOT, ".vajra_state.json")
SKIP_ARCHIVE = {
    "Outputs", "outputs", "workspaces", ".git", ".venv", "__pycache__",
    "venv", "node_modules", ".vajra_state.json",
}


def current_version():
    return __version__


def _run(args, timeout=120):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return -1, "", str(e)


def is_git():
    code, _, _ = _run(["git", "-C", ROOT, "rev-parse", "--is-inside-work-tree"])
    return code == 0


def _branch():
    code, out, _ = _run(["git", "-C", ROOT, "branch", "--show-current"])
    return out or DEFAULT_BRANCH


def _remote(config=None):
    code, url, _ = _run(["git", "-C", ROOT, "remote", "get-url", "origin"])
    if code == 0 and url:
        http = url.replace("git@github.com:", "https://github.com/")
        for pref in ("https://github.com/", "http://github.com/"):
            if http.startswith(pref):
                slug = http[len(pref):].rstrip("/")
                if slug.endswith(".git"):
                    slug = slug[:-4]
                if slug.count("/") == 1:
                    return slug, _branch()
    cfg = config or {}
    return (cfg.get("update_repo", DEFAULT_REPO),
            cfg.get("update_branch", DEFAULT_BRANCH))


def _read_state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_state(head):
    try:
        state = _read_state()
        state["commit"] = head
        with open(STATE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


def _github_head(repo, branch):
    try:
        with urllib.request.urlopen(
                "https://api.github.com/repos/%s/commits/%s"
                % (repo, branch), timeout=15) as r:
            return (json.loads(r.read().decode("utf-8", "replace")) or {}) \
                .get("sha", "")
    except Exception:
        return ""


def _rev_count(rev_a, rev_b):
    code, out, _ = _run(["git", "-C", ROOT, "rev-list", "--count",
                         "%s..%s" % (rev_a, rev_b)])
    try:
        return int(out) if code == 0 and out else -1
    except Exception:
        return -1


def check(config=None):
    """Report (available, detail).

    available is True when an update exists, False when up to date, or None
    when the check itself failed (detail carries the reason). Git installs
    compare local HEAD against the fetched origin branch; archive installs
    compare the remembered commit sha against the GitHub branch head.
    """
    if is_git():
        code, _, err = _run(["git", "-C", ROOT, "remote", "update", "origin"],
                            timeout=180)
        if code != 0:
            return None, err or "git fetch failed"
        behind = _rev_count("HEAD", "origin/%s" % _branch())
        if behind < 0:
            return None, "could not resolve branch refs"
        return behind > 0, "behind upstream by %d commit(s)" % behind
    repo, branch = _remote(config)
    head = _github_head(repo, branch)
    if not head:
        return None, "cannot reach GitHub API"
    return _read_state().get("commit") != head, "upstream @ %s" % head[:7]


def _update_git(log):
    branch = _branch()
    log("[update] git checkout detected — fast-forwarding origin/%s" % branch)
    code, status, _ = _run(["git", "-C", ROOT, "status", "--porcelain"])
    local_mods = [ln for ln in status.splitlines()
                  if ln and not ln.startswith("??")]
    if local_mods:
        log("[!] %d modified/untracked-to-submit file(s) present — commit or "
            "stash them first (update never clobbers local work)" % len(local_mods))
        return 2
    code, _, err = _run(["git", "-C", ROOT, "fetch", "--quiet", "origin"],
                        timeout=180)
    if code != 0:
        log("[!] fetch failed: %s" % err)
        return 1
    behind = _rev_count("HEAD", "origin/%s" % branch)
    if behind <= 0:
        log("[update] already at the latest build (v%s)" % current_version())
        return 0
    ahead = _rev_count("origin/%s" % branch, "HEAD")
    if ahead > 0:
        log("[!] local branch is ahead of origin by %d commit(s) — push "
            "first, then update" % ahead)
        return 2
    code, out, err = _run(["git", "-C", ROOT, "pull", "--ff-only",
                           "origin", branch], timeout=180)
    if code != 0:
        log("[!] fast-forward pull failed: %s" % err)
        return 1
    log("[update] updated to v%s (%s)" % (current_version(),
                                          out.splitlines()[-1] if out else ""))
    return 0


def _safe_extract(targz, dest):
    """Extract the github tarball's single top-level dir into dest."""
    top = None
    with tarfile.open(targz, "r:gz") as tf:
        for m in tf.getmembers():
            first = m.name.split("/", 1)[0]
            if top is None:
                top = first
        root = os.path.join(dest, "root")
        os.makedirs(root, exist_ok=True)
        for m in tf.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) < 2:
                continue
            rel = parts[1]
            target = os.path.abspath(os.path.join(root, rel))
            if os.path.commonpath([os.path.abspath(root), target]) != \
                    os.path.abspath(root):
                continue
            if m.isdir() and rel:
                os.makedirs(target, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                srcf = tf.extractfile(m)
                if srcf is not None:
                    with open(target, "wb") as f:
                        shutil.copyfileobj(srcf, f)
                    os.chmod(target, m.mode & 0o777)
    return root


def _update_archive(config, log):
    repo, branch = _remote(config)
    src = "https://github.com/%s/archive/refs/heads/%s.tar.gz" % (repo, branch)
    log("[update] archive install — downloading %s" % src)
    tmp = tempfile.mkdtemp(prefix="vajra-upd-")
    targz = os.path.join(tmp, "src.tar.gz")
    try:
        urllib.request.urlretrieve(src, targz)
    except Exception as e:
        log("[!] download failed: %r" % e)
        return 1
    try:
        src_root = _safe_extract(targz, tmp)
    except Exception as e:
        log("[!] extract failed: %r" % e)
        return 1

    cfg = os.path.join(ROOT, "config", "config.json")
    cfg_backup = os.path.join(tmp, "config.json.backup")
    if os.path.exists(cfg):
        shutil.copy2(cfg, cfg_backup)

    for entry in sorted(os.listdir(src_root)):
        if entry in SKIP_ARCHIVE:
            continue
        s = os.path.join(src_root, entry)
        d = os.path.join(ROOT, entry)
        if os.path.isdir(s):
            shutil.rmtree(d, ignore_errors=True)
            shutil.move(s, d)
        else:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.move(s, d)

    if os.path.exists(cfg_backup):
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        shutil.copy2(cfg_backup, cfg)

    head = _github_head(repo, branch)
    if head:
        _write_state(head)
    shutil.rmtree(tmp, ignore_errors=True)
    log("[update] in-place archive update complete (v%s)" % current_version())
    return 0


def update(config=None, log=print):
    if is_git():
        return _update_git(log)
    return _update_archive(config, log)