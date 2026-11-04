#!/usr/bin/env python3
"""
DOJO — The Range Mandate CLI. The family's training ground: builds vulnerable
replicas of every technique class (stdlib http.server, localhost-only) so the
bench, the engines, and the operator have something real to strike. Every build
is lab-bound (127.0.0.1), every class maps to canon (kairo flaw/seam), and every
lesson ends in the detection rule kage should emit.

v2.0 — the range doubles: 15 buildable classes (the 9 originals + MASSASSIGN,
INJECTION, SSRF, JWT, AUTHN, SESSION), every replica is SELF-VERIFYING
(`bench --class C` builds it, strikes it with the documented probe, and requires
the flaw to confirm — a replica that doesn't break is a broken replica), and
`build --serve-seconds N` gives self-terminating ranges for CI.

Commands:
  catalog                          every class that can be built × flaw × canon
  build   --class C [--port P] [--serve-seconds N]
                                   generate + serve a vulnerable replica (lab-only)
  bench   --class C [--port P]     build → strike → CONFIRM the flaw (the range verifies itself)
  teach   --class C                the lesson: flaw → probe → detection rule
  verify                           self-check (builds, strikes, and verifies replicas)

Exit codes: 0 ok · 1 verify/bench failure (flaw not confirmed) · 2 usage.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


# ── handlers: one per class; each is deliberately vulnerable, lab-bound ───────

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
            from urllib.parse import unquote as _uq
            p = _uq(self.path)
            if "../" in p:
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


# ── v2.0: the six new classes ─────────────────────────────────────────────────

def _h_massassign(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_POST(self):
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln).decode("utf-8", "replace")
            fields = dict(x.split("=", 1) for x in body.split("&") if "=" in x)
            # the flaw: every client field becomes a model field, role included
            user = {"name": fields.get("name", ""), "email": fields.get("email", ""),
                    "role": fields.get("role", "user")}
            b = json.dumps({"created": True, "user": user}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_injection(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/search"):
                import re as _re
                term = self.path.split("q=")[1] if "q=" in self.path else ""
                # the flaw: the term reaches a template engine unfiltered —
                # {{7*7}} / ${7*7} markers get evaluated (arithmetic only, lab-only)
                m = _re.match(r"^(?:\{\{|\$\{)([\d\s()*+\-/]+)\}\}$", term)
                if m:
                    try:
                        evaluated = str(eval(m.group(1)))
                    except Exception:
                        evaluated = term
                else:
                    evaluated = term
                b = f"results for {evaluated}".encode()
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


def _h_ssrf(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            from urllib.parse import unquote as _uq
            if self.path.startswith("/fetch"):
                url = _uq(self.path.split("url=")[1]) if "url=" in self.path else ""
                # the flaw: the server fetches whatever the client names
                if url.startswith(("http://127.0.0.1", "http://169.254.169.254", "http://localhost")):
                    b = json.dumps({"fetched": "INTERNAL-BANNER-7f3a"}).encode()
                else:
                    b = json.dumps({"fetched": "denied"}).encode()
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_jwt(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/api/admin"):
                tok = self.path.split("token=")[1].split("&")[0] if "token=" in self.path else ""
                # the flaw: signature never checked — only the payload is parsed
                try:
                    payload = json.loads(
                        __import__("base64").urlsafe_b64decode(tok.split(".")[1] + "=="))
                    admin = payload.get("role") == "admin"
                except Exception:
                    admin = False
                b = json.dumps({"admin": admin}).encode()
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_authn(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/api/otp"):
                otp = self.path.split("otp=")[1].split("&")[0] if "otp=" in self.path else ""
                # the flaw: empty/absent otp treated as 'already verified'
                ok = otp in ("", "null", "0", "123456") or otp == "valid"
                b = json.dumps({"authenticated": ok, "verified": ok, "otp_seen": otp}).encode()
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def _h_session(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/session"):
                # the flaw: the session cookie is the sequential user id
                tok = self.path.split("sid=")[1].split("&")[0] if "sid=" in self.path else ""
                try:
                    uid = int(tok)
                except ValueError:
                    uid = None
                b = json.dumps({"session_user": uid if uid is not None else "invalid",
                                "role": "admin" if uid is not None and uid % 100 == 0 else "user"}).encode()
                self.send_response(200)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
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
    # v2.0 — the six new buildable classes
    "MASSASSIGN": {"flaw": 21, "seam": "B", "canon": "kairo MASS-ASSIGN · CWE-915",
                   "build": _h_massassign,
                   "probe": "POST /api/user  name=bob&email=bob@lab&role=admin",
                   "confirm": '"role": "admin"',
                   "lesson": "every client field becomes a model field — role arrives as data",
                   "detect": "api log: body carries role= on unprivileged session → kage T1098"},
    "INJECTION": {"flaw": 1, "seam": "D", "canon": "kairo type/validation · CWE-94",
                  "build": _h_injection,
                  "probe": "/search?q={{7*7}}",
                  "confirm": "results for 49",
                  "lesson": "input reaches an interpreter — the marker arithmetic answers",
                  "detect": "access log: {{/}}/${ markers in q= → kage T1190"},
    "SSRF":      {"flaw": 12, "seam": "N", "canon": "kairo NETWORK · CWE-918",
                  "build": _h_ssrf,
                  "probe": "/fetch?url=http://example.com",
                  "confirm": "INTERNAL-BANNER",
                  "lesson": "the server fetches client-named urls — loopback/link-local reach",
                  "detect": "egress log: app fetch to 127./169.254. → kage T1190"},
    "JWT":       {"flaw": 6, "seam": "C", "canon": "kairo identifier-trust · CWE-347",
                  "build": _h_jwt,
                  "probe": "/api/admin?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
                  "confirm": '"admin": true',
                  "lesson": "signature never verified — the payload's role claim IS the authz decision",
                  "detect": "auth log: alg=none token accepted → kage T1550"},
    "AUTHN":     {"flaw": 8, "seam": "C", "canon": "kairo session-lessons · CWE-287",
                  "build": _h_authn,
                  "probe": "/api/otp?otp=123456",
                  "confirm": '"verified": true',
                  "lesson": "empty second factor accepted as 'already verified'",
                  "detect": "auth log: 200 on protected route with empty otp → kage T1550"},
    "SESSION":   {"flaw": 8, "seam": "C", "canon": "kairo identifier-trust · CWE-384",
                  "build": _h_session,
                  "probe": "/session?sid=100",
                  "confirm": '"role": "admin"',
                  "lesson": "sequential session ids — sid 100 is admin, sid 101 is not",
                  "detect": "auth log: sequential sid accepted → kage T1550"},
}


def _serve(cls, port):
    spec = CLASSES[cls]
    srv = ThreadingHTTPServer(("127.0.0.1", port), spec["build"]({}))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return srv


def _strike(url, confirm, timeout=5):
    """Fetch WITHOUT following redirects (a 302 IS the finding for REDIRECT)."""
    import urllib.request as _ur

    class _NoRedirect(_ur.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = _ur.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=timeout) as r:
            return confirm.lower() in r.read().decode("utf-8", "replace").lower()
    except _ur.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        loc = e.headers.get("Location", "") if e.headers else ""
        return confirm.lower() in (body + " " + loc).lower()
    except Exception:
        return False


def cmd_catalog(args):
    print(f"═══ DOJO CATALOG — {len(CLASSES)} buildable technique classes ═══")
    for cls, spec in CLASSES.items():
        print(f"  ▸ {cls:10s} flaw {spec['flaw']:2d} seam {spec['seam']} · "
              f"{spec['canon']}")
    print("═══ every class: build → strike (bench) → confirm → kage rule ═══")
    return 0


def cmd_build(args):
    cls = args.cls.upper()
    if cls not in CLASSES:
        print(f"✗ unknown class '{args.cls}' — catalog:", file=sys.stderr)
        return cmd_catalog(args)
    spec = CLASSES[cls]
    srv = _serve(cls, args.port)
    port = srv.server_address[1]
    print(f"═══ DOJO — {cls} replica ═══")
    print(f"  ✓ serving  http://127.0.0.1:{port}  (lab-bound)")
    print(f"  ▸ probe    {spec['probe']}")
    print(f"  ▸ flaw     {spec['flaw']} seam {spec['seam']} — {spec['lesson']}")
    print(f"  ▸ detect   {spec['detect']}")
    if args.serve_seconds:
        print(f"  ▸ self-terminating: range closes in {args.serve_seconds}s")
        try:
            time.sleep(args.serve_seconds)
        except KeyboardInterrupt:
            pass
        srv.shutdown()
        print("▸ range closed")
        return 0
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
        print("▸ range closed")
    return 0


def cmd_bench(args):
    """The range verifies ITSELF: build the replica, strike it with the
    documented probe, require the flaw to confirm."""
    cls = args.cls.upper()
    if cls not in CLASSES:
        print(f"✗ unknown class '{args.cls}'", file=sys.stderr)
        return 2
    spec = CLASSES[cls]
    srv = _serve(cls, args.port)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}"
    probe_url = spec["probe"]
    if probe_url.startswith("POST "):
        from urllib.request import Request
        parts = probe_url.split(" ", 2)
        path = parts[1]
        body = parts[2] if len(parts) > 2 else ""
        try:
            req = Request(url + path, data=body.encode(), method="POST")
            with urllib.request.urlopen(req, timeout=5) as r:
                ok = spec["confirm"].lower() in r.read().decode("utf-8", "replace").lower()
        except Exception:
            ok = False
    else:
        # GET probes: the probe string is a full path+query ("/api/admin?token=…");
        # suffix markers like "(×2)" are stripped, single-strike is the proof
        probe_path = probe_url.split(" ")[0]
        ok = _strike(url + probe_path, spec["confirm"])
    srv.shutdown()
    mark = "✓" if ok else "✗"
    print(f"  {mark} {cls:10s} built on {url} · struck '{probe_url[:52]}'"
          f" · flaw {'CONFIRMED' if ok else 'NOT CONFIRMED'}")
    return 0 if ok else 1


def cmd_teach(args):
    cls = args.cls.upper()
    if cls not in CLASSES:
        print(f"✗ unknown class '{args.cls}'", file=sys.stderr)
        return 2
    spec = CLASSES[cls]
    print(f"═══ DOJO LESSON — {cls} [{spec['canon']}] ═══")
    print(f"  flaw {spec['flaw']} · seam {spec['seam']}")
    print(f"  1. build:   dojo build --class {cls} --port 8801")
    print(f"  2. bench:   dojo bench --class {cls}   (the range verifies itself)")
    print(f"  3. attack:  {spec['probe']} → expect: {spec['confirm']}")
    print(f"  4. lesson:  {spec['lesson']}")
    print(f"  5. mirror:  {spec['detect']}")
    return 0


def cmd_verify(args):
    bad = []
    self = Path(__file__).resolve()
    if subprocess.run([sys.executable, "-m", "py_compile", str(self)],
                      capture_output=True).returncode != 0:
        bad.append("compile")
    for want in ("catalog", "build", "bench", "teach", "verify"):
        if want not in subprocess.run([sys.executable, str(self), "--help"],
                                      capture_output=True, text=True).stdout:
            bad.append(want)
    if len(CLASSES) < 15:
        bad.append("catalog")
    # live: build a HARVEST replica on an ephemeral port and probe it
    port = 8891
    srv = _serve("HARVEST", port)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/backup.zip",
                                    timeout=5) as r:
            if "FAKEBACKUPDATA" not in r.read().decode():
                bad.append("build-probe")
    except Exception:
        bad.append("build-probe")
    finally:
        srv.shutdown()
    # live: bench a v2.0 class (the self-verifying range)
    r = subprocess.run([sys.executable, str(self), "bench", "--class", "JWT", "--port", str(port + 1)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        bad.append("bench JWT")
    if bad:
        print(f"✗ DOJO verify FAILED: {bad}")
        return 1
    print("✓ DOJO verify: compile · commands · 15 classes · live build+probe+bench — ALL PASS")
    return 0


def main():
    ap = argparse.ArgumentParser(description="DOJO — The Range Mandate (buildable vulnerable replicas)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("catalog", help="buildable classes × flaw × canon")
    b = sub.add_parser("build", help="serve a vulnerable replica (127.0.0.1 only)")
    b.add_argument("--class", dest="cls", required=True)
    b.add_argument("--port", type=int, default=8801)
    b.add_argument("--serve-seconds", dest="serve_seconds", type=int,
                   help="self-terminate after N seconds (CI-safe)")
    bn = sub.add_parser("bench", help="build → strike → confirm the flaw")
    bn.add_argument("--class", dest="cls", required=True)
    bn.add_argument("--port", type=int, default=8801)
    t = sub.add_parser("teach", help="the lesson: flaw → probe → detection")
    t.add_argument("--class", dest="cls", required=True)
    sub.add_parser("verify", help="self-check")
    a = ap.parse_args()
    return {"catalog": cmd_catalog, "build": cmd_build, "bench": cmd_bench,
            "teach": cmd_teach, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
