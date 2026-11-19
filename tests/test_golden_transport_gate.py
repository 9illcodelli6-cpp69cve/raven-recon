"""GOLDEN / characterization tests — the `Handler` transport gate (Wave 3 oracle).

Locks the CURRENT behaviour of the request gate in `server.Handler` BEFORE Wave 3
thins the Handler and routes bodies through RavenRuntime services. Per
RUNTIME_ARCHITECTURE.md §10 and CANONICAL_ARCHITECTURE §8 risk 3 (fail-closed
terminal / transport), the gate must stay byte-for-byte equivalent even as route
bodies are delegated.

Locked invariants:
  * /api/health is open; every other /api route needs a single valid X-RAVEN-Token;
  * the token compare is single-header + constant-time: wrong token -> 403,
    two token headers -> 403, exact token -> 200;
  * non-loopback Host -> 403; loopback Host -> served;
  * state-changing requests (POST/PUT) require token AND an allowed Origin;
    a cross-origin request with a valid token is still 403;
  * request framing hardening: chunked Transfer-Encoding -> 501, oversize
    Content-Length -> 413, duplicate/invalid Content-Length -> 400, each on a
    connection that is then closed (no smuggling into the next request).

Loopback only; no external host is contacted.

Run:  python -m pytest tests/test_golden_transport_gate.py -q
"""
import http.client
import os
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

from raven.api import server


class _WireHandler(server.Handler):
    body_read_timeout = 0.35
    timeout = 2.0

    def log_message(self, *_):
        pass


class TransportGateAuth(unittest.TestCase):
    """Host / token / Origin gate, driven with http.client (single socket per call)."""

    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-golden-gate-")
        os.chdir(cls._tmp)
        server.use_workspace("goldengate")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _WireHandler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        store = server.STATE.get("store")
        if store is not None:
            store.close()
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)

    def _status(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            r.read()
            return r.status
        finally:
            c.close()

    # ── token gate ─────────────────────────────────────────────────────────
    def test_health_is_open_without_token(self):
        self.assertEqual(self._status("GET", "/api/health"), 200)

    def test_api_without_token_is_403(self):
        self.assertEqual(self._status("GET", "/api/summary"), 403)

    def test_api_with_wrong_token_is_403(self):
        self.assertEqual(self._status("GET", "/api/summary",
                                      {"X-RAVEN-Token": "not-the-token"}), 403)

    def test_api_with_valid_token_is_200(self):
        self.assertEqual(self._status("GET", "/api/summary",
                                      {"X-RAVEN-Token": server.SESSION_TOKEN}), 200)

    # ── Host gate ──────────────────────────────────────────────────────────
    def test_non_loopback_host_is_403(self):
        self.assertEqual(self._status("GET", "/api/health", {"Host": "evil.example"}), 403)

    def test_loopback_host_is_served(self):
        self.assertEqual(self._status("GET", "/api/health",
                                      {"Host": f"localhost:{self.port}"}), 200)

    # ── Origin / CSRF gate (state-changing only) ─────────────────────────────
    def test_cross_origin_post_with_valid_token_is_403(self):
        self.assertEqual(self._status("POST", "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": "http://evil.example",
            "Content-Type": "application/json",
        }, '{"method":"GET","url":"https://example.com/"}'), 403)

    def test_same_origin_post_with_valid_token_passes_gate(self):
        # Auth passes (not 403); the request itself is refused/blocked downstream.
        status = self._status("POST", "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Type": "application/json",
        }, '{"method":"GET","url":"https://blocked.invalid.test/"}')
        self.assertNotEqual(status, 403)

    def test_put_scope_without_token_is_403(self):
        self.assertEqual(self._status("PUT", "/api/scope",
                                      {"Content-Type": "application/json"},
                                      '{"name":"x","include":["x.test"],"ports":[80]}'), 403)


class TransportGateFraming(unittest.TestCase):
    """Raw-wire framing hardening — one socket so an unread body would leak into
    the trailing /api/health probe and be caught."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _WireHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(2)

    @contextmanager
    def _conn(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            with sock.makefile("rb") as stream:
                yield sock, stream

    def _raw(self, method="POST", path="/api/missing", headers=(), body=b"", auth=True):
        rows = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{self.port}"]
        if auth:
            rows.append(f"X-RAVEN-Token: {server.SESSION_TOKEN}")
        rows.extend(headers)
        return ("\r\n".join(rows) + "\r\n\r\n").encode("ascii") + body

    def _read_response(self, stream):
        statusline = stream.readline()
        self.assertTrue(statusline.startswith(b"HTTP/1.1 "), statusline)
        status = int(statusline.split()[1])
        headers = {}
        while True:
            line = stream.readline()
            self.assertTrue(line, "EOF in response headers")
            if line == b"\r\n":
                break
            key, value = line.decode().split(":", 1)
            headers[key.lower()] = value.strip()
        stream.read(int(headers.get("content-length", 0)))
        return status, headers

    def _assert_rejected_and_closed(self, request, status):
        with self._conn() as (sock, stream):
            # A trailing unauthenticated health request would turn into a second
            # response iff the first request's body/framing were mishandled.
            sock.sendall(request + self._raw("GET", "/api/health", auth=False))
            actual, headers = self._read_response(stream)
            self.assertEqual(actual, status)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(stream.read(1), b"")  # socket closed; nothing smuggled

    def test_chunked_transfer_encoding_is_501(self):
        self._assert_rejected_and_closed(
            self._raw(headers=("Transfer-Encoding: chunked",),
                      body=b"5\r\nhello\r\n0\r\n\r\n"), 501)

    def test_oversize_content_length_is_413(self):
        self._assert_rejected_and_closed(
            self._raw(headers=(f"Content-Length: {_WireHandler.max_request_body + 1}",)), 413)

    def test_duplicate_content_length_is_400(self):
        self._assert_rejected_and_closed(
            self._raw(headers=("Content-Length: 1", "Content-Length: 2"), body=b"{}"), 400)

    def test_duplicate_token_headers_is_403(self):
        # Exactly one X-RAVEN-Token is required; two valid copies must still fail.
        with self._conn() as (sock, stream):
            req = self._raw("GET", "/api/summary", headers=(
                f"X-RAVEN-Token: {server.SESSION_TOKEN}",), auth=True)  # auth=True adds a second copy
            sock.sendall(req)
            status, _ = self._read_response(stream)
            self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
