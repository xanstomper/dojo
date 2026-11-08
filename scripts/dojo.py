#!/usr/bin/env python3
"""
DOJO — The Range Mandate CLI. The family's training ground: builds vulnerable
replicas of every technique class (stdlib http.server, localhost-only) so the
bench, the engines, and the operator have something real to strike. Every build
is lab-bound (127.0.0.1), every class maps to canon (kairo flaw/seam), and every
lesson ends in the detection rule kage should emit.

v3.0 — the range quintuples: 80 buildable classes (16 hand-built archetypes +
the 64-class surface tier: 16 flaws × API/MQTT/DEVICE/CLOUD surfaces), every
replica is SELF-VERIFYING
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


# ── v2.1 (spydermonkey v5.17) — the hardware class: a simulated smart-home
# device registry (Tuya/ESP-class strip controller) with an enumerable
# reserved-master IDOR — lab-bound, no real hardware needed to train the flaw.

def _h_hwdev(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/api/v1/device/state"):
                dev = self.path.split("id=")[1].split("&")[0] if "id=" in self.path else ""
                # the flaw: the reserved MASTER controller (id 0000) is served
                # to whoever asks — the registry never checks the caller
                if dev == "0000":
                    b = json.dumps({"type": "master_controller",
                                    "master_key": "MASTERKEY-7f3a",
                                    "state": "armed"}).encode()
                elif dev:
                    b = json.dumps({"type": "led_strip", "device": dev,
                                    "brightness": 255, "state": "on"}).encode()
                else:
                    b = json.dumps({"error": "device id required"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
    return H


def _h_statebypass(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def _handle(self):
            if self.path.startswith("/api/v1/order/transition"):
                q = self.path.split("?", 1)[1] if "?" in self.path else ""
                params = dict(kv.split("=", 1) for kv in q.split("&") if "=" in kv)
                order, to = params.get("order", ""), params.get("to", "")
                # the flaw: the transition handler NEVER checks the flow's
                # prerequisite — "shipped" is reachable straight from created
                flow = {"created": ["paid"], "paid": ["shipped", "refunded"],
                        "shipped": ["delivered"], "delivered": [], "refunded": []}
                allowed = flow.get(ORDERS.get(order, "created"), [])
                if to in flow and (to in allowed or True):   # the guard is MISSING
                    ORDERS[order] = to
                    b = json.dumps({"order": order, "state": to,
                                    "accepted": True}).encode()
                    code = 200
                else:
                    b = json.dumps({"error": "unknown transition"}).encode()
                    code = 400
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        do_GET = do_POST = _handle
    return H


ORDERS = {"1001": "created"}


def _h_math(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/api/v1/wallet/split"):
                q = self.path.split("?", 1)[1] if "?" in self.path else ""
                params = dict(kv.split("=", 1) for kv in q.split("&") if "=" in kv)
                try:
                    amount = float(params.get("amount", "0"))
                    n = int(params.get("n", "1"))
                except ValueError:
                    b = json.dumps({"error": "bad amount/n"}).encode()
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                # the flaw: float division + per-share rounding DOWN — the
                # credited total drifts below the real amount (residue vanishes)
                share = round(amount / n, 2)
                credited = round(share * n, 2)
                b = json.dumps({"amount": amount, "shares": n,
                                "share": share,
                                "total_credited": credited,
                                "residue": round(amount - credited, 2)}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
    return H


def _h_hwflash(srv_state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.path.startswith("/api/v1/device/firmware"):
                q = self.path.split("?", 1)[1] if "?" in self.path else ""
                params = dict(kv.split("=", 1) for kv in q.split("&") if "=" in kv)
                dev = params.get("dev", "")
                signed = params.get("signed", "true").lower() != "false"
                # the flaw: the update path lets the CLIENT declare the payload
                # pre-signed — "signed=false" flashes anyway, no guard
                if dev and not signed:
                    b = json.dumps({"device": dev, "flashed": True,
                                    "signature": "unverified",
                                    "version": "1.0.1-unsigned"}).encode()
                elif dev:
                    b = json.dumps({"device": dev, "flashed": True,
                                    "signature": "verified",
                                    "version": "1.0.1"}).encode()
                else:
                    b = json.dumps({"error": "device required"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                b = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
    return H


# ── v3.0 (spydermonkey v6.0) — THE SURFACE TIER: 16 archetypes × 4 delivery
# surfaces (API / MQTT / DEVICE / CLOUD) = 64 generated classes. Same flaw
# semantics as the archetype, translated to a different protocol surface.
# Every generated replica self-verifies exactly like the hand-built ones.

_SURFACES = {
    "API":    {"path": "api/v1",  "flavor": "json service"},
    "MQTT":   {"path": "mqtt",    "flavor": "simulated broker"},
    "DEVICE": {"path": "api/v1/device", "flavor": "device registry"},
    "CLOUD":  {"path": "api/v1/cloud",  "flavor": "cloud control plane"},
}

# archetype → (probe builder fn(prefix), confirm marker, lesson, detect)
_ARCS = {
    "BOUNDARY":  (lambda p: f"/{p}/orders?uid=000-ADMIN", '"secret"',
                  "scope id from query — the session's uid is never consulted",
                  "api log: uid != session uid → kage T1068"),
    "REPLAY":    (lambda p: f"POST /{p}/webhook  body=tx&amt=1", '"dup": 1',
                  "no idempotency key — the same logical order lands twice",
                  "request log: same body 2x in 60s → kage T1550"),
    "HARVEST":   (lambda p: f"/{p}/backup.zip", "FAKEBACKUP",
                  "sensitive artifact served from the web root",
                  "access log: backup path + 200 → kage T1552"),
    "TRAVERSAL": (lambda p: f"/{p}/files?name=../../etc/passwd", "root:x:",
                  "path param never normalized — ../ escapes the root",
                  "access log: ../ in uri + 200 → kage rule"),
    "DIRECTORY": (lambda p: f"/{p}/static/", "backup.zip",
                  "autoindex left on — entries enumerable",
                  "access log: listing 200 → kage rule"),
    "XSS":       (lambda p: f"/{p}/search?q=XSSMARK", "XSSMARK",
                  "query echoed unencoded — reflection without context-encoding",
                  "access log: markup in q= reflected → kage rule"),
    "REDIRECT":  (lambda p: f"/{p}/r?url=https://evil.example", "evil.example",
                  "Location built from user input — open redirect",
                  "access log: 302 Location crosses origins → kage rule"),
    "CRYPTO":    (lambda p: f"/{p}/state", '"cipher": "rc4"',
                  "legacy cipher advertised — downgrade classes",
                  "tls scan: rc4 present → kage rule"),
    "NETWORK":   (lambda p: f"/{p}/net", '"open"',
                  "service banners exposed — version-pinned classes",
                  "banner grab: stale strings → kage rule"),
    "MASSASSIGN": (lambda p: f"POST /{p}/user  name=bob&role=admin", '"role": "admin"',
                  "every client field becomes a model field — role arrives as data",
                  "api log: body carries role= on low session → kage T1098"),
    "INJECTION": (lambda p: f"/{p}/search?q={{{{7*7}}}}", "for 49",
                  "input reaches a template engine — arithmetic marker answers",
                  "access log: {{}} markers in q= → kage T1190"),
    "SSRF":      (lambda p: f"/{p}/fetch?url=http://127.0.0.1", "INTERNAL-BANNER",
                  "server fetches client-named urls — loopback reach",
                  "egress log: fetch to 127. → kage T1190"),
    "JWT":       (lambda p: f"/{p}/admin?token=eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", '"admin": true',
                  "signature never verified — the payload claim IS the authz",
                  "auth log: alg=none token accepted → kage T1550"),
    "AUTHN":     (lambda p: f"/{p}/otp?otp=", '"verified": true',
                  "empty second factor accepted as 'already verified'",
                  "auth log: 200 on protected route with empty otp → kage T1550"),
    "SESSION":   (lambda p: f"/{p}/session?sid=100", '"role": "admin"',
                  "sequential session ids — sid 100 is admin, sid 101 is not",
                  "auth log: sequential sid accepted → kage T1550"),
    "HWDEV":     (lambda p: f"/{p}/state?id=0000", '"master_key"',
                  "reserved master device id enumerable — registry never checks who asks",
                  "api log: registry hit for reserved id 0000 → kage T1550"),
}


def _h_surface(archetype, surface):
    prefix = _SURFACES[surface]["path"]
    flavor = _SURFACES[surface]["flavor"]
    confirm, lesson, detect = _ARCS[archetype][1], _ARCS[archetype][2], _ARCS[archetype][3]

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def _out(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs, unquote as _uq
            from urllib.parse import urlsplit as _split
            p = self.path
            _par = parse_qs(urlparse(p).query)
            def _one(*names):
                for n in names:
                    if n in _par and _par[n]:
                        return _par[n][0]
                return None
            if _split(p).path.startswith(f"/{prefix}/orders"):
                v = _one("uid", "org_id", "user_id", "account_id", "order_id") or "me"
                self._out({"uid": v, "secret": "SECRET-9f2c", "orders": [1]})
            elif archetype == "TRAVERSAL" and "../" in _uq(p):
                self._out({"file": "root:x:0:0:root:/root:/bin/bash"})
            elif archetype == "XSS" and _split(p).path.startswith(f"/{prefix}/search"):
                v = _one("q", "search", "term", "name") or ""
                self._out({"results": v})
            elif archetype == "REDIRECT" and _split(p).path.startswith(f"/{prefix}/r"):
                u = _one("url", "next", "redirect", "dest") or "/"
                self.send_response(302)
                self.send_header("Location", u)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif archetype == "CRYPTO" and _split(p).path.startswith(f"/{prefix}/state"):
                self._out({"tls": "v1.0", "cipher": "rc4"})
            elif archetype == "NETWORK" and _split(p).path.startswith(f"/{prefix}/net"):
                self._out({"open": [21, 22, 3306], "banner": "vsftpd 2.3.4"})
            elif archetype == "INJECTION" and _split(p).path.startswith(f"/{prefix}/search"):
                import re as _re
                term = _one("q", "search", "name", "filter", "sort", "msg") or ""
                m = _re.match(r"^(?:\{\{|\$\{|<%=|#\{)([\d\s()*+\-/]+)\}?\}?$", term)
                if m:
                    try:
                        term = str(eval(m.group(1)) if any(c in m.group(1) for c in "*/+-") else term)
                    except Exception:
                        term = term
                self._out({"results": "for " + term})
            elif archetype == "SSRF" and _split(p).path.startswith(f"/{prefix}/fetch"):
                u = _one("url", "uri", "fetch", "target", "src") or ""
                if any(x in u for x in ("127.0.0.1", "169.254.169.254", "localhost",
                                        "[::1]", "0x7f000001", "2130706433")):
                    self._out({"fetched": "INTERNAL-BANNER-7f3a"})
                else:
                    self._out({"fetched": "denied"})
            elif archetype == "JWT" and _split(p).path.startswith(f"/{prefix}/admin"):
                import base64 as _b64
                tok = _one("token") or ""
                admin = False
                try:
                    payload = json.loads(_b64.urlsafe_b64decode(tok.split(".")[1] + "=="))
                    admin = payload.get("role") == "admin"
                except Exception:
                    admin = False
                self._out({"admin": admin})
            elif archetype == "AUTHN" and _split(p).path.startswith(f"/{prefix}/otp"):
                otp = _one("otp", "token", "code", "nonce") if (_one("otp", "token", "code", "nonce") is not None) else ""
                self._out({"verified": otp in ("", "null", "0", "123456", "undefined", "none", "false"), "otp_seen": otp})
            elif archetype == "SESSION" and _split(p).path.startswith(f"/{prefix}/session"):
                try:
                    uid = int(_one("sid", "session", "id") or "")
                except Exception:
                    uid = None
                self._out({"role": "admin" if uid is not None and uid % 100 == 0 else "user"})
            elif archetype == "HWDEV" and _split(p).path.startswith(f"/{prefix}/state"):
                dev = _one("id", "device") or ""
                if dev == "0000":
                    self._out({"type": "master_controller", "master_key": "MASTERKEY-7f3a"})
                else:
                    self._out({"type": "led_strip", "device": dev, "state": "on"})
            elif archetype == "DIRECTORY" and p.endswith("/static/"):
                self._out({"listing": ["backup.zip", "db.sql", ".env"]})
            elif archetype == "HARVEST" and p.endswith("backup.zip"):
                self._out({"backup": "FAKEBACKUPDATA"})
            else:
                self._out({"error": "nope"}, 404)
        def do_POST(self):
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln).decode("utf-8", "replace")
            fields = dict(x.split("=", 1) for x in body.split("&") if "=" in x)
            if archetype == "REPLAY" and "/webhook" in self.path:
                H._hits = getattr(H, "_hits", 0) + 1
                out = {"accepted": True, "dup": H._hits}
                if "role" in fields:
                    out["role"] = fields["role"]
                self._out(out)
            elif archetype == "MASSASSIGN" and "/user" in self.path:
                self._out({"role": fields.get("role", "user"), "name": fields.get("name", "")})
            else:
                self._out({"error": "nope"}, 404)
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
                  "build": _h_traversal, "probe": "/files?name=",
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
                   "probe": "POST /api/user  name=bob&email=bob@lab",
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
    "HWDEV":     {"flaw": 6, "seam": "E",
                  "canon": "spydermonkey hardware-canon plane 6 · kairo HWFLASH · CWE-639",
                  "build": _h_hwdev,
                  "probe": "/api/v1/device/state?id=0000",
                  "confirm": '"master_key"',
                  "lesson": "reserved master device id enumerable — the registry never checks who asks (smart-home IDOR)",
                  "detect": "api log: device registry hit for reserved id 0000 → kage T1550"},
    "STATEBYPASS": {"flaw": 5, "seam": "B",
                    "canon": "kairo STATEBYPASS · kairo REPLAY · CWE-354",
                    "build": _h_statebypass,
                    "probe": "/api/v1/order/transition?order=1001&to=shipped",
                    "confirm": '"state": "shipped"',
                    "lesson": "the transition handler never checks the flow's prerequisite — out-of-order jumps land undocumented states",
                    "detect": "api log: state transition skipping prerequisite → kage T1047"},
    "MATH":      {"flaw": 10, "seam": "C",
                  "canon": "kairo MATH · CWE-1335",
                  "build": _h_math,
                  "probe": "/api/v1/wallet/split?amount=10.03&n=3",
                  "confirm": '"total_credited": 10.02',
                  "lesson": "float division + per-share rounding-down — the credited total drifts and the residue vanishes into the operator's favor",
                  "detect": "api log: reconcile mismatch between amount and credited totals → kage T1565"},
    "HWFLASH":   {"flaw": 6, "seam": "E",
                  "canon": "kairo HWFLASH · CWE-494",
                  "build": _h_hwflash,
                  "probe": "/api/v1/device/firmware?dev=cam7&signed=false",
                  "confirm": '"signature": "unverified"',
                  "lesson": "the update path lets the CLIENT declare the payload pre-signed — signature skip is a request parameter",
                  "detect": "device log: firmware flash with signature=unverified → kage T1600"},
}

# ── v3.0 surface tier (must run AFTER CLASSES exists) ───────────────────────
for _arc in _ARCS:
    for _surf in _SURFACES:
        _cls = f"{_arc}-{_surf}"
        _probe = _ARCS[_arc][0](_SURFACES[_surf]["path"])
        CLASSES[_cls] = {"flaw": 3, "seam": "S",
                         "canon": f"generated surface tier: {_arc} × {_surf} (spydermonkey v6.0)",
                         "build": (lambda srv_state, _a=_arc, _s=_surf: _h_surface(_a, _s)),
                         "probe": _probe,
                         "confirm": _ARCS[_arc][1], "lesson": _ARCS[_arc][2],
                         "detect": _ARCS[_arc][3]}


def _serve(cls, port):
    spec = CLASSES[cls]
    H = spec["build"]({})          # build returns the HANDLER CLASS
    _p = spec["probe"]
    _path = _p[5:].strip().split(" ")[0] if _p.startswith("POST ") else _p.split(" ")[0]
    links = [_path]

    class _Idx(H):
        # the landing page — a REAL app links its endpoints; the crawler feeds on it
        def do_GET(self):
            if self.path == "/" and links[0] != "/":
                b = (f"<html><body><h1>{cls} demo app</h1>"
                     + "".join(f'<div><a href="{u}">{u}</a></div>' for u in links)
                     + "</body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return
            base = super()
            if hasattr(base, "do_GET"):
                return base.do_GET()
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.write(b"")
            return

    srv = ThreadingHTTPServer(("127.0.0.1", port), _Idx)
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
    if len(CLASSES) < 80:
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
    print("✓ DOJO verify: compile · commands · 80 classes · live build+probe+bench — ALL PASS")
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
