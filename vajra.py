#!/usr/bin/env python3
"""
  ██╗   ██╗ █████╗      ██╗██████╗  █████╗
  ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
  ██║   ██║███████║ ██  ██║██████╔╝███████║
  ╚██╗ ██╔╝██╔══██║ ╚██╗██╔╝██╔══██╗██╔══██║
   ╚████╔╝ ██║  ██║  ╚███╔╝ ██║  ██║██║  ██║
    ╚═══╝  ╚═╝  ╚═╝   ╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝

  VAJRA — All-in-One Automated Penetration Testing Framework
  recon + network + web + exploitation + post-exploitation + intelligence
"""
import os
import sys
import json
import argparse
from core.workspace import _slug, Workspace
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import PROJECT_ROOT, load_json
from modules import get_modules

BANNER_COLORS = "\033[95m\033[1m", "\033[0m"
DISCLAIMER = """
[!] LEGAL DISCLAIMER
    VAJRA is a professional security assessment framework. Running it against
    systems you do not own or do not have EXPLICIT WRITTEN AUTHORIZATION to
    test is ILLEGAL in most jurisdictions. The authors accept no liability for
    misuse. By proceeding you confirm you have authorization for every target.
"""


def show_banner(color=True):
    art = r"""
  ██╗   ██╗ █████╗      ██╗██████╗  █████╗
  ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
  ██║   ██║███████║ ██  ██║██████╔╝███████║
  ╚██╗ ██╔╝██╔══██║ ╚██╗██╔╝██╔══██╗██╔══██║
   ╚████╔╝ ██║  ██║  ╚███╔╝ ██║  ██║██║  ██║
    ╚═══╝  ╚═╝  ╚═╝   ╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝"""
    if color and sys.stdout.isatty():
        print("\033[95m\033[1m%s\033[0m" % art)
    else:
        print(art)
    print("   ⚡ VAJRA — automated penetration testing framework")
    print("     by Pintu Kumar Sutradhar\n")


def import_findings_and_report(findings_file, targets, output_root):
    """Import findings from a JSON file and generate reports for the given targets."""
    import json
    import os
    from core.database import Database
    from core.report import build_data, render_html, render_json, render_markdown
    from core.intelligence import Intelligence
    from core.engine import sanitize_target_name

    # Load findings
    with open(findings_file, 'r') as f:
        findings_list = json.load(f)

    # Group findings by target
    findings_by_target = {}
    for f in findings_list:
        t = f.get('target')
        if t not in findings_by_target:
            findings_by_target[t] = []
        findings_by_target[t].append(f)

    # Process each target
    for t in targets:
        t_display = t.display
        tname = sanitize_target_name(t_display)
        tdir = os.path.join(output_root, tname)
        os.makedirs(tdir, exist_ok=True)
        evdir = os.path.join(tdir, "evidence")
        os.makedirs(evdir, exist_ok=True)

        db_path = os.path.join(tdir, "data.sqlite")
        db = Database(db_path)

        # Insert findings for this target (if any)
        if t_display in findings_by_target:
            for f in findings_by_target[t_display]:
                db.add_finding(f)

        # Create a mock engine for report generation
        class MockEngine:
            def __init__(self, db, target, profile, outdir):
                self.db = db
                self.targets = [target]
                self.intel = Intelligence()
                self.profile = profile
                self.outdir = outdir
                self.state = {
                    "tech": [],
                    "subdomains": [],
                    "os_guess": "",
                    "evasion_all": []
                }

        engine = MockEngine(db, t, "default", tdir)

        # Build data and render reports
        data = build_data(engine)
        html = render_html(data)
        json_out = render_json(data)
        md = render_markdown(data)

        # Write reports
        with open(os.path.join(tdir, 'report.html'), 'w') as f:
            f.write(html)
        with open(os.path.join(tdir, 'report.json'), 'w') as f:
            f.write(json_out)
        with open(os.path.join(tdir, 'report.md'), 'w') as f:
            f.write(md)

        print(f"[+] Imported {len(findings_by_target.get(t_display, []))} findings for {t_display}")
        print(f"[+] Report written to {tdir}/report.html")
        print(f"[+] Report written to {tdir}/report.json")
        print(f"[+] Report written to {tdir}/report.md")


def parse_args():
    ap = argparse.ArgumentParser(
        prog="vajra",
        description="VAJRA - all-in-one automated penetration testing "
                    "framework (recon, network, web, exploitation, "
                    "post-exploitation, adaptive evasion)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""examples:
  python3 vajra.py -t 10.10.10.5 --profile full --yes
  python3 vajra.py -t https://example.org --profile quick
  python3 vajra.py -t 192.168.1.0/24 -p top1000 -o reports
  python3 vajra.py -t targets.txt --profile webonly --format html
  python3 vajra.py -t http://app.local --profile full --aggressive --yes
outputs:  Outputs/vajra_<run>/<target>/  → report.html/json/md · sqlite ·
          vajra.log · evidence/
profiles: quick | full | vast | stealth | webonly | recon
  vast      = everything everywhere: all 65535 TCP ports, UDP probes, deep
              wordlists (>100k), 400-page crawl, full exploitation scope.
  full      = all TCP ports + deep wordlists (no UDP).
  quick     = top-100 ports, shallow but fast (default).

wordlist tiers: fast lists always ship; deep tiers (115k users / 148k
passwords / 16k dirs / 18k subs) activate on --profile full|vast or
--aggressive""")
    ap.add_argument("-t", "--target",
                    help="IP / CIDR / URL / comma list / @file")
    ap.add_argument("-p", "--ports",
                    help="port spec: 80 | 22-1000 | top100 | top1000 | extended | all")
    ap.add_argument("--profile", default="quick",
                    choices=["quick", "full", "vast", "stealth", "webonly",
                             "recon"],
                    help="scan profile (default: quick; vast = full 65535-port"
                         " sweep + UDP + deep wordlists)")
    ap.add_argument("--threads", type=int, help="worker threads override")
    ap.add_argument("--timeout", type=float, help="per-request timeout override")
    ap.add_argument("--delay", type=float, help="delay between HTTP requests (stealth)")
    ap.add_argument("-o", "--output", default="Outputs",
                    help="output root (default: Outputs/ — per-target bundles)")
    ap.add_argument("--format", default="all",
                    choices=["html", "json", "md", "pdf", "all"],
                    help="report format")
    ap.add_argument("--modules", help="comma list of modules to run only")
    ap.add_argument("--exclude-modules", dest="exclude_modules", default="",
                    help="comma list of modules to skip")
    ap.add_argument("--no-brute", action="store_true",
                    help="disable brute-force module")
    ap.add_argument("--aggressive", action="store_true",
                    help="deep wordlists + intrusive exploitation "
                         "(incl. reverse-session delivery)")
    ap.add_argument("--lhost", default="auto",
                    help="your callback IP for reverse sessions "
                         "(default: auto-detect via eth0/default route)")
    ap.add_argument("--lport", type=int, default=None,
                    help="callback port (default: first free of "
                         "4444,4545,1234,5555,8080,1337,9001)")
    ap.add_argument("--listener", action="store_true",
                    help="standalone multi-session callback handler")
    ap.add_argument("--ai", action="store_true",
                    help="enable the local Ollama+Qwen3 8B brain "
                         "(auto-installs if missing; off by default)")
    ap.add_argument("--ai-select", action="store_true",
                    help="mission mode: Qwen3 inspects scan state and picks "
                         "the next task for each target (auto stops; "
                         "exploitation still needs --aggressive)")
    ap.add_argument("--udp", action="store_true",
                    help="include UDP service probes (DNS/NTP/SNMP)")
    ap.add_argument("--syn", action="store_true",
                    help="raw SYN scan instead of connect scan (root)")
    ap.add_argument("--ad-user", default=None,
                    help="Active Directory username (enables LDAP bind / "
                         "kerberoast prep)")
    ap.add_argument("--ad-pass", default=None, help="AD password")
    ap.add_argument("--nthash", default=None,
                    help="NT hash for pass-the-hash (LM:NT or bare NT)")
    ap.add_argument("--web-user", default=None,
                    help="webapp username — turns the scan into an "
                         "AUTHENTICATED crawl/scan of the application")
    ap.add_argument("--web-pass", default=None, help="webapp password")
    ap.add_argument("--web-login", default=None,
                    help="explicit login URL (auto-discovers the login "
                         "form otherwise)")
    ap.add_argument("--web-otp", default=None,
                    help="static MFA/OTP code for the login form, "
                         "e.g. 123456")
    ap.add_argument("--web-totp-secret", dest="web_totp_secret", default=None,
                    help="base32 TOTP secret — VAJRA generates the current "
                         "(RFC 6238) code at login time")
    ap.add_argument("--no-external-intel", dest="no_external_intel",
                    action="store_true",
                    help="disable third-party intel lookups entirely")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--workspace", default=None,
                    help="workspace name for snapshots + retest delta "
                         "(default: auto per-target; dirs under "
                         "Outputs/workspaces/)")
    ap.add_argument("--socks5", default=None,
                    help="SOCKS5 proxy for egress, e.g. 127.0.0.1:9050 "
                         "(web + raw probes via the tunnel)")
    ap.add_argument("--cve-update", action="store_true",
                    help="when the offline KB misses a product:version, "
                         "query the live CVE API (cached)" )
    ap.add_argument("--oob", action="store_true",
                    help="run an out-of-band HTTP callback listener for blind "
                         "SSRF / RCE detection (auto in full/vast)")
    ap.add_argument("--oob-port", dest="oob_port", type=int, default=None,
                    help="fixed local port for the OOB listener "
                         "(default: ephemeral)")
    ap.add_argument("--user-agent", dest="user_agent", help="custom User-Agent")
    ap.add_argument("--wordlists-dir", dest="wordlists_dir",
                    help="override wordlist directory")
    ap.add_argument("--yes", action="store_true", help="accept legal disclaimer non-interactively")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="-v info/debug, -vv trace")
    ap.add_argument("--selftest", action="store_true", help="run internal QA tests")
    ap.add_argument("--list-modules", dest="list_modules", action="store_true")
    ap.add_argument("--version", action="version", version="VAJRA by Pintu Kumar Sutradhar")
    ap.add_argument("--export-findings", metavar="FILE", help="export findings to JSON file and exit")
    ap.add_argument("--import-findings", metavar="FILE", help="import findings from JSON file and generate report, then exit")
    return ap.parse_args()


def run_listener_console(args):
    import time as _t
    from core.listener import Listener, detect_lhost, pick_lport, run_interactive

    lhost = args.lhost if args.lhost not in ("auto", "", None) else detect_lhost()
    lport = args.lport or pick_lport()
    holder = {}

    def on_session(sess):
        n = len(holder.get("sessions", []))
        print("\n[*] SESSION #%d connected from %s:%d" %
              (n + 1, sess.addr[0], sess.addr[1]))

    ln = Listener("0.0.0.0", lport, on_session=on_session)
    ln.start()
    waited = 0.0
    while ln.port is None and waited < 5:
        _t.sleep(0.1)
        waited += 0.1
    if ln.port is None:
        print("[!] could not bind a listener port")
        return 1
    print("[*] LHOST : %s" % lhost)
    print("[*] LPORT : %d%s" % (ln.port,
                                "  (requested %d busy)" % lport if ln.port != lport else ""))
    print("[*] listening — waiting for callbacks…  ('sessions','use N','exit')")
    try:
        while True:
            try:
                cmd = input("vajra-listener> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if cmd == "exit":
                break
            elif cmd == "sessions":
                sess = ln.sessions
                if not sess:
                    print("  no sessions yet")
                    continue
                for i, sx in enumerate(sess):
                    print("  #%d %s:%d (since %s)" % (i + 1, sx.addr[0],
                                                      sx.addr[1],
                                                      _t.strftime("%H:%M:%S",
                                                                  sx.opened_at)))
            elif cmd.startswith("use"):
                try:
                    idx = int(cmd.split()[1]) - 1
                    sess = ln.sessions[idx]
                except Exception:
                    print("  usage: use <session-number>")
                    continue
                run_interactive(sess)
            elif cmd:
                print("  commands: sessions | use N | exit")
    finally:
        ln.stop()
    return 0


def main():
    args = parse_args()
    show_banner(color=not args.no_color)

    if args.selftest:
        from core import selftest
        return selftest.run_all()

    if args.list_modules:
        print(" %-24s %-9s %s" % ("MODULE", "PHASE", "DESCRIPTION"))
        print(" " + "-" * 78)
        for m in get_modules():
            print(" %-24s %-9s %s" % (m["name"], m["phase"], m["desc"]))
        return 0

    if args.listener:
        return run_listener_console(args)

    if args.export_findings:
        if not args.target:
            print("[!] --export-findings requires a target to locate the "
                  "workspace")
            return 1
        from core.target import expand_targets
        targets = expand_targets(args.target)
        if not targets:
            print("[!] no valid targets specified")
            return 1
        ws = Workspace(str(targets[0].display))
        if not os.path.exists(ws.latest_path):
            print("[!] no workspace snapshot found for target %s (run a scan "
                  "or --import-findings first)" % targets[0].display)
            return 1
        findings = ws.merged_findings()
        ws.export_findings(args.export_findings)
        print("[+] exported %d finding(s) to %s"
              % (len(findings), args.export_findings))
        return 0

    if args.import_findings:
        # Import findings and generate reports
        if not args.target:
            print("[!] --import-findings requires a target to determine output directory")
            return 1
        from core.target import expand_targets
        targets = expand_targets(args.target)
        if not targets:
            print("[!] no valid targets specified")
            return 1
        import_findings_and_report(args.import_findings, targets, args.output or "Outputs")
        return 0

    if not args.target:
        print("[!] target required: use -t <ip|cidr|url|@file>")
        return 1

    if not args.yes:
        print(DISCLAIMER)
        try:
            ans = input("Confirm you have authorization to test the target(s) [y/N]: ")
        except EOFError:
            return 1
        if ans.strip().lower() not in ("y", "yes"):
            print("[!] aborted - authorization not confirmed")
            return 1

    config = {}
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    if cfg_path.exists():
        try:
            with open(cfg_path, encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            print("[!] warning: config.json invalid (%r) - using defaults" % e)

    from core.engine import Engine
    engine = Engine(args, config)
    try:
        engine.run()
        return 0
    except KeyboardInterrupt:
        print("\n[!] interrupted by user — writing partial report...")
        try:
            engine.generate_reports()
        except Exception:
            pass
        return 130


if __name__ == "__main__":
    sys.exit(main())
