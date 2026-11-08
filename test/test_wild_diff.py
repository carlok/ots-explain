# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""tools/wild_diff.py: the GitHub token goes to api.github.com only, and a refusal says what to do. No network."""
import importlib.util, io, os, sys, unittest, urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("wild_diff", os.path.join(ROOT, "tools", "wild_diff.py"))
W = importlib.util.module_from_spec(spec); spec.loader.exec_module(W)


class FakeResponse(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


class WildDiffAuth(unittest.TestCase):
    def seen(self, url, env):
        sent = []
        def fake_urlopen(req, timeout=None): sent.append(req); return FakeResponse(b"{}")
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(W.urllib.request, "urlopen", fake_urlopen):
            W.get(url)
        return sent[0]

    def clean(self): return {k: "" for k in ("GH_TOKEN", "GITHUB_TOKEN")}

    def test_token_sent_to_the_api(self):
        req = self.seen("https://api.github.com/search/code?q=x", {**self.clean(), "GH_TOKEN": "t0k"})
        self.assertEqual(req.get_header("Authorization"), "Bearer t0k")

    def test_token_not_sent_to_raw(self):
        req = self.seen("https://raw.githubusercontent.com/a/b/HEAD/x.ots", {**self.clean(), "GH_TOKEN": "t0k"})
        self.assertIsNone(req.get_header("Authorization"))

    def test_no_token_no_header(self):
        req = self.seen("https://api.github.com/search/code?q=x", self.clean())
        self.assertIsNone(req.get_header("Authorization"))

    def test_github_token_is_the_fallback(self):
        req = self.seen("https://api.github.com/search/code?q=x", {**self.clean(), "GITHUB_TOKEN": "fall"})
        self.assertEqual(req.get_header("Authorization"), "Bearer fall")

    def test_401_is_not_retried_and_says_what_to_do(self):
        calls = []
        def refuse(req, timeout=None):
            calls.append(1); raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
        with mock.patch.object(W.urllib.request, "urlopen", refuse), mock.patch.object(W.time, "sleep"):
            with self.assertRaises(SystemExit) as cm: W.search(5, 60)
        self.assertEqual(len(calls), 1)
        self.assertIn("GH_TOKEN", str(cm.exception))


if __name__ == "__main__": unittest.main()
