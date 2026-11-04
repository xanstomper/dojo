#!/usr/bin/env python3
"""
DOJO — The Range Mandate CLI. The family's training ground: builds vulnerable
replicas of every technique class (stdlib http.server, localhost-only) so the
bench, the engines, and the operator have something real to strike. Every
build is lab-bound (127.0.0.1), every class maps to canon (kairo flaw/seam),
and every lesson ends in the detection rule kage should emit.

Commands:
  catalog                     every class that can be built × flaw × canon
  build   --class C [--port P]     generate + serve a vulnerable replica (lab-only)
  teach   --class C            the lesson: flaw → probe → detection rule
  verify                      self-check (builds one replica and probes it)

Exit codes: 0 ok · 1 verify failure · 2 usage.
"""
import argparse
import json
import re
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# class → {flaw, seam, canon, lesson, handler-factory}
def _h_boundary(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            org = "acme"
            if "org_id=" in self.path:
                org = self.path.split("org_id=")[1].split("&")[0]
            b = json.dumps({"org": org, "orders": [1, 2, 3]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_harvest(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path in ("/backup.zip", "/.env", "/.git/config"):
                b = b"FAKEBACKUPDATA"
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
            else:
                b = b"lab"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_replay(srv_state):
    class H(BaseHTTPRequestHandler):
        hits = 0
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path == "/api/webhook":
                H.hits += 1
                b = json.dumps({"accepted": True, "dup_effects": H.hits}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                self.send_response(404)
                self.end_headers()
    return H


def _h_traversal(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if "../" in self.path:
                b = b"root:x:0:0:root:/root:/bin/bash\n"
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_directory(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.rstrip("/") == "/static":
                b = b"backup.zip  db.sql  .env\n"
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_xss(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/search"):
                term = self.path.split("q=")[1] if "q=" in self.path else ""
                b = f"results for {term}".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_redirect(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/r"):
                url = self.path.split("url=")[1] if "url=" in self.path else "/"
                self.send_response(302)
                self.send_header("Location", url)
            else:
                self.send_response(404)
            self.end_headers()
    return H


def _h_crypto(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            b = json.dumps({"tls": "v1.0 enabled", "cipher": "RC4-SHA"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_network(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            b = json.dumps({"open": [21, 22, 3306], "banner": "vsftpd 2.3.4"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


CLASSES = {
    "BOUNDARY":  {"flaw": 6, "seam": "E", "canon": "kairo BOUNDARY · CWE-639",
                  "build": _h_boundary, "probe": "/api/orders?org_id=foreign",
                  "confirm": '"org": "foreign"',
                  "lesson": "scope-id trusted from the query — the session's org is never consulted",
                  "detect": "api log: org_id != session org → kage T1068 rule"},
    "REPLAY":    {"flaw": 2, "seam": "F", "canon": "kairo REPLAY · CWE-294",
                  "build": _h_replay, "probe": "/api/webhook (×2)",
                  "confirm": '"accepted": true',
                  "lesson": "no idempotency key — the same logical request lands twice",
                  "detect": "request log: same (method,path,body-hash) 2× in 60s → kage T1550"},
    "HARVEST":   {"flaw": 15, "seam": "G", "canon": "shukaku BACKUP · CWE-538",
                  "build": _h_harvest, "probe": "/backup.zip",
                  "confirm": "FAKEBACKUPDATA",
                  "lesson": "sensitive artifacts on the web root — backups, env, git",
                  "detect": "access log: (backup|dump|\\.env|\\.git) + 200 → kage T1552"},
    "TRAVERSAL": {"flaw": 3, "seam": "D", "canon": "kairo type/path · CWE-22",
                  "build": _h_traversal, "probe": "/files?name=../../etc/passwd",
                  "confirm": "root:x:0:0",
                  "lesson": "path param never normalized — ../ escapes the root",
                  "detect": "access log: ../ in uri + 200 → kage rule"},
    "DIRECTORY": {"flaw": 15, "seam": "G", "canon": "CWE-548",
                  "build": _h_directory, "probe": "/static/",
                  "confirm": "backup.zip",
                  "lesson": "autoindex left on — entries enumerable",
                  "detect": "access log: /static/ 200 + listing → kage rule"},
    "XSS":       {"flaw": 3, "seam": "D", "canon": "CWE-79",
                  "build": _h_xss, "probe": "/search?q=<svg>",
                  "confirm": "<svg>",
                  "lesson": "query echoed unencoded — reflection without context-encoding",
                  "detect": "access log: markup in q= reflected → kage rule"},
    "REDIRECT":  {"flaw": 7, "seam": "A", "canon": "kairo DOMTAKE · CWE-601",
                  "build": _h_redirect, "probe": "/r?url=https://evil.example",
                  "confirm": "evil.example",
                  "lesson": "Location built from user input — open redirect / r==-relay",
                  "detect": "access log: 302 Location crosses origins → kage rule"},
    "CRYPTO":    {"flaw": 10, "seam": "J", "canon": "kairo CRYPTO · CWE-327",
                  "build": _h_crypto, "probe": "/",
                  "confirm": '"tls": "v1.0',
                  "lesson": "legacy tls/cipher advertised — downgrade + weak-cipher classes",
                  "detect": "tls scan: v1.0/RC4 present → kage rule"},
    "NETWORK":   {"flaw": 14, "seam": "N", "canon": "kairo HDRADIO/NETWORK · CWE-200",
                  "build": _h_network, "probe": "/",
                  "confirm": '"open"',
                  "lesson": "service banners exposed — version-pinned exploit classes",
                  "detect": "banner grab: stale service strings → kage rule"},
}


def cmd_catalog(args):
    print(f"═══ DOJO CATALOG — {len(CLASSES)} buildable technique classes ═══")
    for cls, spec in CLASSES.items():
        print(f"  ▸ {cls:10s} flaw {spec['flaw']:2d} seam {spec['seam']} · "
              f"{spec['canon']}")
    print("═══ every class: build → probe → confirm → kage rule ═══")
    return 0


def cmd_build(args):
    cls = args.cls.upper()
    if cls not in CLASSES:
        print(f"✗ unknown class '{args.cls}' — catalog:", file=sys.stderr)
        return cmd_catalog(args)
    spec = CLASSES[cls]
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), spec["build"]({}))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"═══ DOJO — {cls} replica ═══")
    print(f"  ✓ serving  http://127.0.0.1:{args.port}  (lab-bound, Ctrl-C to stop)")
    print(f"  ▸ probe    {spec['probe']}")
    print(f"  ▸ flaw     {spec['flaw']} seam {spec['seam']} — {spec['lesson']}")
    print(f"  ▸ detect   {spec['detect']}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
        print("▸ range closed")
    return 0


def cmd_teach(args):
    cls = args.cls.upper()
    if cls not in CLASSES:
        print(f"✗ unknown class '{args.cls}'", file=sys.stderr)
        return 2
    spec = CLASSES[cls]
    print(f"═══ DOJO LESSON — {cls} [{spec['canon']}] ═══")
    print(f"  flaw {spec['flaw']} · seam {spec['seam']}")
    print(f"  1. build:   dojo build --class {cls} --port 8801")
    print(f"  2. attack:  {spec['probe']} → expect: {spec['confirm']}")
    print(f"  3. lesson:  {spec['lesson']}")
    print(f"  4. mirror:  {spec['detect']}")
    return 0


def cmd_verify(args):
    bad = []
    self = Path(__file__).resolve()
    if subprocess.run([sys.executable, "-m", "py_compile", str(self)],
                      capture_output=True).returncode != 0:
        bad.append("compile")
    for want in ("catalog", "build", "teach", "verify"):
        if want not in subprocess.run([sys.executable, str(self), "--help"],
                                      capture_output=True, text=True).stdout:
            bad.append(want)
    if len(CLASSES) < 9:
        bad.append("catalog")
    # live: build a HARVEST replica on an ephemeral port and probe it
    port = 8891
    srv = ThreadingHTTPServer(("127.0.0.1", port), CLASSES["HARVEST"]["build"]({}))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/backup.zip",
                                    timeout=5) as r:
            if "FAKEBACKUPDATA" not in r.read().decode():
                bad.append("build-probe")
    except Exception:
        bad.append("build-probe")
    finally:
        srv.shutdown()
    if bad:
        print(f"✗ DOJO verify FAILED: {bad}")
        return 1
    print("✓ DOJO verify: compile · commands · 9 classes · live build+probe — ALL PASS")
    return 0


def main():
    ap = argparse.ArgumentParser(description="DOJO — The Range Mandate (buildable vulnerable replicas)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("catalog", help="buildable classes × flaw × canon")
    b = sub.add_parser("build", help="serve a vulnerable replica (127.0.0.1 only)")
    b.add_argument("--class", dest="cls", required=True)
    b.add_argument("--port", type=int, default=8801)
    t = sub.add_parser("teach", help="the lesson: flaw → probe → detection")
    t.add_argument("--class", dest="cls", required=True)
    sub.add_parser("verify", help="self-check")
    a = ap.parse_args()
    return {"catalog": cmd_catalog, "build": cmd_build, "teach": cmd_teach,
            "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
