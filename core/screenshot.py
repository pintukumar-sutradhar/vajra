"""Headless-browser screenshot evidence.

Captures a full-page PNG of a URL using Playwright + a system Chromium, so a
confirmed web finding can ship a real visual proof in its evidence folder.
Everything is best-effort: if Playwright or a browser is unavailable (or the
target refuses to render) the scanner falls back to the textual PoC/evidence
and the scan is never aborted.

Find a browser in this order:
  1. $VAJRA_BROWSER / $CHROME_PATH / $CHROMIUM_PATH
  2. a ``chromium`` / ``chrome`` binary on PATH
"""
import os
import re
import shutil
import sys

_BROWSER_NAMES = ("chromium", "chromium-browser", "google-chrome", "chrome",
                  "google-chrome-stable")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _site_fallback_paths():
    """Extra directories that may host a user/system playwright + its deps
    when this (possibly root-owned, system-isolated) venv hides them —
    typical of Kali setups where tools land under ~/.local or dist-packages."""
    paths = []
    try:
        import site
        user = site.getusersitepackages()
        if user and os.path.isdir(user):
            paths.append(user)
    except Exception:
        pass
    base = getattr(sys, "base_prefix", sys.prefix)
    for extra in (os.path.join("lib", "python%d.%d" %
                               sys.version_info[:2], "dist-packages"),
                  os.path.join("lib", "python%d.%d" %
                               sys.version_info[:2], "site-packages"),
                  os.path.join("local", "lib", "python%d.%d" %
                               sys.version_info[:2], "dist-packages")):
        p = os.path.join(base, extra)
        if p and os.path.isdir(p) and p not in paths:
            paths.append(p)
    if os.path.isdir("/usr/lib/python3/dist-packages"):
        paths.append("/usr/lib/python3/dist-packages")
    return paths


def _ensure_playwright():
    """Bring Playwright (and its deps) onto sys.path if the venv hides a
    user/system install — common on Kali where tools land under ~/.local."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        pass
    added = [p for p in _site_fallback_paths() if p not in sys.path]
    # Prepend so higher-priority entries (user site, pip installs) stay
    # ahead of system dist-packages, which may carry a Debian-bundled
    # playwright with a broken node driver.
    for p in reversed(added):
        sys.path.insert(0, p)
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


_TMP_UNSET = object()
_cached_browser = _TMP_UNSET


def _find_browser():
    global _cached_browser
    if _cached_browser is not _TMP_UNSET:
        return _cached_browser
    cands = []
    for var in ("VAJRA_BROWSER", "CHROME_PATH", "CHROMIUM_PATH"):
        p = os.environ.get(var)
        if p and os.path.isfile(p):
            cands.append(p)
    for name in _BROWSER_NAMES:
        p = shutil.which(name)
        if p:
            cands.append(p)
    found = next((p for p in cands if os.path.isfile(p)), None)
    _cached_browser = found
    return found


def available():
    """True if we expect `capture` to work on this host (Playwright present
    and a usable browser binary found)."""
    return _ensure_playwright() and _find_browser() is not None


def first_url(text):
    """Pull the first http(s) URL out of free-form finding text, if any."""
    if not text:
        return ""
    m = _URL_RE.search(text)
    if not m:
        return ""
    return m.group(0).rstrip("),.;!?]\"")


def capture(url, out_path, timeout=8000, user_agent=None):
    """Best-effort full-page PNG screenshot of ``url`` -> ``out_path``.

    Returns True on success. Never raises: every failure is treated as
    'screenshot unavailable' so the caller can fall back to text evidence.
    HTTP error pages still render, so they are legitimately captured too.
    """
    browser = _find_browser()
    if not browser or not _ensure_playwright():
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            launched = pw.chromium.launch(
                executable_path=browser, headless=True,
                args=["--no-sandbox", "--disable-gpu",
                      "--disable-dev-shm-usage"])
            try:
                ctx = launched.new_context(
                    ignore_https_errors=True,
                    user_agent=user_agent or
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
                page = ctx.new_page()
                page.set_default_timeout(max(1000, int(timeout)))
                page.goto(url, wait_until="domcontentloaded",
                          timeout=max(1000, int(timeout)))
                # Render for a beat so async content paints before capture.
                page.wait_for_timeout(400)
                try:
                    page.screenshot(path=out_path, full_page=True)
                except Exception:
                    page.screenshot(path=out_path)
            finally:
                ctx.close()
                launched.close()
        return os.path.isfile(out_path) and os.path.getsize(out_path) > 0
    except Exception:
        return False