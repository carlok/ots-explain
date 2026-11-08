#!/usr/bin/env python3
# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""ots_api.py - a small REST API in front of verify_ots.py and ots_stamp.py. Standard library only.

    python3 python/ots_api.py                       # http://127.0.0.1:8787, offline, no network features
    python3 python/ots_api.py --allow-network       # enable ledger checks, stamping and upgrading
    python3 python/ots_api.py --token SECRET        # require "Authorization: Bearer SECRET"
    python3 python/ots_api.py --cors https://my.app # allow one browser origin (default: none)

Design choices (the spec of the report is spec/SPEC.md; the HTTP contract is spec/openapi.json):
  * It binds to 127.0.0.1 unless you pass --host. It is a helper for your own tools, not a public service.
  * It takes digests, never files: hash on the client (the JS client does), so nothing large or private is uploaded.
  * Everything that touches the network is OFF unless --allow-network, and even then the server only contacts
    explorers and calendars from fixed allow-lists (the defaults plus --esplora-allow / --calendar-allow), so a request
    cannot make it fetch an arbitrary URL (no SSRF).
  * /v1/verify returns exactly the canonical JSON that `verify_ots.py --json` prints, byte for byte.
  * Request bodies are never logged.
"""
import argparse
import base64
import binascii
import hmac
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ots as V  # noqa: E402
import ots_stamp as S  # noqa: E402

API_VERSION = "1"
MAX_BODY = 16 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, status, code, message):
        Exception.__init__(self, message)
        self.status, self.code, self.message = status, code, message


def b64decode(s, what):
    if not isinstance(s, str): raise ApiError(400, "bad_request", "%s must be a base64 string" % what)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        try: return base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4), validate=True)
        except (binascii.Error, ValueError): raise ApiError(400, "bad_request", "%s is not valid base64" % what)


def get_digest(v):
    if v is None: return None
    if not isinstance(v, str) or not V._is_hex(v): raise ApiError(400, "bad_request", "digest must be a hex string")
    return v.lower()


def norm(url): return url.rstrip("/")


class Config:
    def __init__(self, allow_network=False, token=None, cors=None, esplora_allow=(), calendar_allow=(), fetch=None, call=None, max_body=MAX_BODY):
        self.allow_network, self.token, self.cors, self.max_body = allow_network, token, cors, max_body
        self.esplora_allowed = {norm(s["base"]): s for s in V.DEFAULT_SERVERS}
        for u in esplora_allow: self.esplora_allowed[norm(u)] = {"name": norm(u), "base": norm(u)}
        self.calendars_allowed = [norm(c) for c in list(S.KNOWN_CALENDARS) + list(calendar_allow)]
        self.fetch = fetch or V.http_fetch()
        self.call = call or S.http_call()


def need_network(cfg):
    if not cfg.allow_network: raise ApiError(403, "network_disabled", "this server was started without --allow-network")


# ------------------------------------------------------------------------------------------ operations

def op_verify(cfg, params, proof_bytes):
    digest = get_digest(params.get("digest"))
    ledger = None
    want = params.get("ledger")
    if want:
        need_network(cfg)
        servers = []
        if want is True or want == "default" or want == "true": servers = [dict(s) for s in V.DEFAULT_SERVERS]
        elif isinstance(want, dict) and isinstance(want.get("servers"), list):
            for s in want["servers"]:
                base = norm(s["base"] if isinstance(s, dict) and "base" in s else s) if isinstance(s, (str, dict)) else None
                if not base or base not in cfg.esplora_allowed:
                    raise ApiError(400, "server_not_allowed", "ledger server %r is not on the allow-list (start the server with --esplora-allow)" % (s,))
                servers.append(dict(cfg.esplora_allowed[base]))
        else: raise ApiError(400, "bad_request", "ledger must be true or {\"servers\": [...]}")
        if not servers: raise ApiError(400, "bad_request", "no ledger servers given")
        ledger = {"fetch": cfg.fetch, "servers": servers}
    report = V.build_report(proof_bytes, digest_hex=digest, ledger=ledger)
    return report


def op_stamp(cfg, body):
    need_network(cfg)
    digest = get_digest(body.get("digest"))
    if digest is None or len(digest) != 64: raise ApiError(400, "bad_request", "digest must be 64 hex characters (SHA-256)")
    cals = body.get("calendars") or S.DEFAULT_CALENDARS
    if not isinstance(cals, list) or not all(isinstance(c, str) for c in cals) or not cals: raise ApiError(400, "bad_request", "calendars must be a list of URLs")
    for c in cals:
        if norm(c) not in cfg.calendars_allowed: raise ApiError(400, "calendar_not_allowed", "calendar %r is not on the allow-list (start the server with --calendar-allow)" % c)
    log = []
    try:
        proof = S.stamp_digest(bytes.fromhex(digest), cals, cfg.call, log=log.append)
    except RuntimeError as e:
        raise ApiError(502, "no_calendar", str(e) + ": " + "; ".join(log))
    return {"proof_b64": base64.b64encode(proof).decode(), "status": "pending", "log": log}


def op_upgrade(cfg, body):
    need_network(cfg)
    proof = b64decode(body.get("proof_b64"), "proof_b64")
    log = []
    try:
        new, changed, status = S.upgrade_proof(proof, cfg.call, cfg.calendars_allowed, log.append)
    except V.OtsError as e:
        raise ApiError(400, "bad_proof", "the proof cannot be read: " + e.code)
    return {"proof_b64": base64.b64encode(new).decode(), "changed": changed, "status": status, "log": log}


def op_permalink(body):
    digest = get_digest(body.get("digest"))
    proof = b64decode(body.get("proof_b64"), "proof_b64")
    base = body.get("base")
    if not isinstance(base, str) or not base.startswith(("https://", "http://", "file://")) or any(c in base for c in "?#"):
        raise ApiError(400, "bad_request", "base must be a URL without ? or #")
    pu = body.get("proof_url")
    if pu is not None and not isinstance(pu, str): raise ApiError(400, "bad_request", "proof_url must be a string")
    if not digest: raise ApiError(400, "bad_request", "digest is required")
    return {"url": V.encode_permalink(base, digest, proof, pu or None)}


def op_permalink_decode(body):
    url = body.get("url")
    if not isinstance(url, str): raise ApiError(400, "bad_request", "url must be a string")
    d = V.decode_permalink(url)
    return {"digest": d["h"], "proof_b64": base64.b64encode(d["ots"]).decode() if d["ots"] is not None else None, "proof_url": d["proof"]}


# ------------------------------------------------------------------------------------------ HTTP

def make_handler(cfg):
    spec_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "openapi.json")

    class H(BaseHTTPRequestHandler):
        server_version = "ots-explain/" + V.VERSION
        protocol_version = "HTTP/1.1"

        def log_message(self, *a): pass  # never log URLs or bodies

        def _send(self, status, body, ctype="application/json", extra=None):
            if isinstance(body, str): body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("application/json", "text/")) else ""))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if cfg.cors:
                self.send_header("Access-Control-Allow-Origin", cfg.cors)
                self.send_header("Vary", "Origin")
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD": self.wfile.write(body)

        def _json(self, status, obj, extra=None): self._send(status, V.canonical_json(obj) + "\n", extra=extra)

        def _fail(self, e): self._json(e.status, {"error": {"code": e.code, "message": e.message}})

        def _auth(self):
            if cfg.token is None: return
            got = self.headers.get("Authorization", "")
            if not hmac.compare_digest(got.encode(), ("Bearer " + cfg.token).encode()): raise ApiError(401, "unauthorized", "missing or wrong bearer token")

        def _body(self):
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower(): raise ApiError(411, "length_required", "send a Content-Length")
            n = self.headers.get("Content-Length")
            if n is None or not n.isdigit(): raise ApiError(411, "length_required", "send a Content-Length")
            if int(n) > cfg.max_body: raise ApiError(413, "too_large", "body larger than %d bytes" % cfg.max_body)
            return self.rfile.read(int(n))

        def _json_body(self):
            try: obj = json.loads(self._body().decode("utf-8"))
            except (ValueError, UnicodeDecodeError): raise ApiError(400, "bad_request", "body must be JSON")
            if not isinstance(obj, dict): raise ApiError(400, "bad_request", "body must be a JSON object")
            return obj

        def do_OPTIONS(self):
            if not cfg.cors: return self._send(204, b"")
            self._send(204, b"", extra={"Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "600"})

        def do_GET(self):
            try:
                path = urllib.parse.urlparse(self.path).path
                if path == "/v1/health": return self._json(200, {"ok": True, "version": V.VERSION, "api": API_VERSION, "report_spec": "ots-explain-report/1", "network": cfg.allow_network})
                if path == "/openapi.json":
                    with open(spec_path, "rb") as f: return self._send(200, f.read())
                self._auth()
                raise ApiError(404, "not_found", "no such endpoint")
            except ApiError as e: self._fail(e)

        def do_POST(self):
            try:
                self._auth()
                u = urllib.parse.urlparse(self.path)
                q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                if u.path == "/v1/verify":
                    ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    if ctype == "application/json":
                        body = self._json_body()
                        proof = b64decode(body.get("proof_b64"), "proof_b64")
                        params = body
                    else:  # raw .ots bytes, parameters in the query string
                        proof = self._body()
                        params = {"digest": q.get("digest"), "ledger": q.get("ledger") in ("1", "true", "default")}
                    report = op_verify(cfg, params, proof)
                    fmt = q.get("format") or params.get("format")
                    extra = {"X-Verdict": report["verdict"]["status"]}
                    if fmt == "text": return self._send(200, V.render_text(report, bool(q.get("steps") or params.get("steps"))), "text/plain", extra)
                    return self._json(200, report, extra)
                if u.path == "/v1/stamp": return self._json(200, op_stamp(cfg, self._json_body()))
                if u.path == "/v1/upgrade": return self._json(200, op_upgrade(cfg, self._json_body()))
                if u.path == "/v1/permalink": return self._json(200, op_permalink(self._json_body()))
                if u.path == "/v1/permalink/decode": return self._json(200, op_permalink_decode(self._json_body()))
                raise ApiError(404, "not_found", "no such endpoint")
            except ApiError as e: self._fail(e)
            except Exception:  # a bug must not leak a traceback to the client
                self._json(500, {"error": {"code": "internal", "message": "internal error"}})

        do_HEAD = do_GET

    return H


def serve(host="127.0.0.1", port=0, **kw):
    cfg = Config(**kw)
    srv = ThreadingHTTPServer((host, port), make_handler(cfg))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def main(argv=None):
    ap = argparse.ArgumentParser(description="REST API for verify_ots.py and ots_stamp.py (see the module docstring).")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--allow-network", action="store_true", help="enable ledger checks, stamping and upgrading")
    ap.add_argument("--token", default=os.environ.get("OTS_API_TOKEN"), help="require this bearer token (or env OTS_API_TOKEN)")
    ap.add_argument("--cors", help="one browser origin to allow, e.g. https://my.app")
    ap.add_argument("--esplora-allow", action="append", default=[], metavar="URL", help="extra Esplora base URL requests may name")
    ap.add_argument("--calendar-allow", action="append", default=[], metavar="URL", help="extra calendar URL requests may name")
    ap.add_argument("--max-body", type=int, default=MAX_BODY)
    a = ap.parse_args(argv)
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.token:
        print("refusing to listen on %s without --token (this is a helper, not a public service)" % a.host, file=sys.stderr); return 2
    cfg = Config(a.allow_network, a.token, a.cors, a.esplora_allow, a.calendar_allow, max_body=a.max_body)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(cfg)); srv.daemon_threads = True
    print("ots-explain API on http://%s:%d  network=%s auth=%s cors=%s" % (a.host, srv.server_address[1], "on" if a.allow_network else "off", "token" if a.token else "none", a.cors or "off"), flush=True)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    return 0


if __name__ == "__main__": sys.exit(main())
