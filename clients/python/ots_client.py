# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""A tiny client for the ots-explain REST API (python/ots_api.py). Standard library only.

    from ots_client import OtsApi
    api = OtsApi("http://127.0.0.1:8787")
    report = api.verify(proof=open("a.pdf.ots", "rb").read(), digest="03ba20...")
    report["verdict"]["status"]        # "PASS" | "FAIL" | "SKIP"

The API takes digests, not files: hash locally first (hashlib.sha256), so the file never leaves your machine.
No direct use of the server needed either: `import verify_ots` gives the same report in-process (see the README).
"""
import base64
import json
import urllib.error
import urllib.request


class OtsApiError(Exception):
    def __init__(self, status, code, message):
        Exception.__init__(self, "%s %s: %s" % (status, code, message))
        self.status, self.code, self.message = status, code, message


class OtsApi:
    def __init__(self, base_url="http://127.0.0.1:8787", token=None, timeout=60.0):
        self.base, self.token, self.timeout = base_url.rstrip("/"), token, timeout

    def _call(self, method, path, body=None, raw=False):
        headers = {"Accept": "application/json"}
        data = None
        if body is not None: data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        if self.token: headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r: status, text = r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as e: status, text = e.code, e.read().decode("utf-8", "replace")
        if raw and status == 200: return text
        try: obj = json.loads(text)
        except ValueError: raise OtsApiError(status, "bad_response", "the server did not answer JSON")
        if status != 200:
            err = obj.get("error", {}) if isinstance(obj, dict) else {}
            raise OtsApiError(status, err.get("code", "error"), err.get("message", text))
        return obj

    def health(self): return self._call("GET", "/v1/health")

    def verify(self, proof, digest=None, ledger=None, steps=False):
        body = {"proof_b64": base64.b64encode(proof).decode()}
        if digest: body["digest"] = digest
        if ledger: body["ledger"] = ledger
        if steps: body["steps"] = True
        return self._call("POST", "/v1/verify", body)

    def verify_text(self, proof, digest=None, ledger=None, steps=False):
        body = {"proof_b64": base64.b64encode(proof).decode(), "format": "text", "steps": steps}
        if digest: body["digest"] = digest
        if ledger: body["ledger"] = ledger
        return self._call("POST", "/v1/verify", body, raw=True)

    def stamp(self, digest, calendars=None):
        r = self._call("POST", "/v1/stamp", dict({"digest": digest}, **({"calendars": calendars} if calendars else {})))
        return {"proof": base64.b64decode(r["proof_b64"]), "status": r["status"], "log": r["log"]}

    def upgrade(self, proof):
        r = self._call("POST", "/v1/upgrade", {"proof_b64": base64.b64encode(proof).decode()})
        return {"proof": base64.b64decode(r["proof_b64"]), "changed": r["changed"], "status": r["status"], "log": r["log"]}

    def permalink(self, digest, proof, base, proof_url=None):
        return self._call("POST", "/v1/permalink", dict({"digest": digest, "proof_b64": base64.b64encode(proof).decode(), "base": base}, **({"proof_url": proof_url} if proof_url else {})))["url"]

    def decode_permalink(self, url):
        r = self._call("POST", "/v1/permalink/decode", {"url": url})
        return {"digest": r["digest"], "proof": base64.b64decode(r["proof_b64"]) if r["proof_b64"] is not None else None, "proof_url": r["proof_url"]}
