"""Raw loopback-wire regressions: body boundaries, deadlines and persistent HTTP.

The tests use one socket for pipelines so automatic client reconnection cannot
hide an unread body or a prematurely closed normal keep-alive connection.
"""
import json
import socket
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from raven.api import server


class WireHandler(server.Handler):
    body_read_timeout = 0.35
    timeout = 2.0

    def log_message(self, *_):
        pass


class HTTPFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), WireHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(2)

    @contextmanager
    def connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            with sock.makefile("rb") as stream:
                yield sock, stream

    def request(self, method="POST", path="/api/missing", headers=(), body=b"", auth=True):
        rows = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{self.port}"]
        if auth:
            rows.append(f"X-RAVEN-Token: {server.SESSION_TOKEN}")
        rows.extend(headers)
        return ("\r\n".join(rows) + "\r\n\r\n").encode("ascii") + body

    def response(self, stream):
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
        body = stream.read(int(headers.get("content-length", 0)))
        return status, headers, body

    def assert_rejected_and_closed(self, request, status):
        with self.connection() as (sock, stream):
            # If body/framing were left unread, the trailing health request would
            # become another response. A rejection must terminate this exact socket.
            sock.sendall(request + self.request("GET", "/api/health", auth=False))
            actual, headers, _ = self.response(stream)
            self.assertEqual(actual, status)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(stream.read(1), b"")

    def test_invalid_and_duplicate_content_length_close(self):
        for values in (("-1",), ("+2",), ("abc",), ("1, 1",), ("1", "1"), ("1", "2")):
            with self.subTest(values=values):
                self.assert_rejected_and_closed(self.request(
                    headers=tuple("Content-Length: " + v for v in values), body=b"{}"), 400)

    def test_oversized_and_huge_integer_lengths_close_without_body(self):
        for length in (str(WireHandler.max_request_body + 1), "9" * 5000):
            with self.subTest(length=length[:20]):
                self.assert_rejected_and_closed(self.request(
                    headers=(f"Content-Length: {length}",)), 413)

    def test_transfer_encoding_and_conflicting_length_close(self):
        for headers in (("Transfer-Encoding: chunked",),
                        ("Transfer-Encoding: chunked", "Content-Length: 2"),
                        ("Transfer-Encoding: identity",)):
            with self.subTest(headers=headers):
                self.assert_rejected_and_closed(self.request(
                    headers=headers, body=b"2\r\n{}\r\n0\r\n\r\n"), 501)

    def test_get_body_is_consumed_before_next_request(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request("GET", "/api/health", ("Content-Length: 4",), b"DATA", False)
                         + self.request("GET", "/api/health", auth=False))
            for _ in range(2):
                status, headers, body = self.response(stream)
                self.assertEqual(status, 200)
                self.assertNotEqual(headers.get("connection"), "close")
                self.assertTrue(json.loads(body)["ok"])

    def test_unknown_route_body_is_consumed_on_same_socket(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(headers=("Content-Length: 2",), body=b"{}")
                         + self.request("GET", "/api/health", auth=False))
            self.assertEqual(self.response(stream)[0], 404)
            self.assertEqual(self.response(stream)[0], 200)

    def test_invalid_or_nonobject_json_returns_400_and_keeps_framing(self):
        for body in (b"NOT JSON", b"[]", b"null", b"5", b'"string"', b"\xff"):
            with self.subTest(body=body), self.connection() as (sock, stream):
                sock.sendall(self.request(headers=(f"Content-Length: {len(body)}",), body=body)
                             + self.request("GET", "/api/health", auth=False))
                self.assertEqual(self.response(stream)[0], 400)
                self.assertEqual(self.response(stream)[0], 200)

    def test_unauthorized_request_does_not_wait_for_body_or_continue(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(path="/api/send", auth=False,
                                     headers=("Content-Length: 100", "Expect: 100-continue")))
            status, headers, _ = self.response(stream)
            self.assertEqual(status, 403)  # first response, never a 100 or timeout
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(stream.read(1), b"")

    def test_cross_origin_request_does_not_wait_for_body(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(path="/api/send", headers=(
                "Content-Length: 100", "Origin: http://evil.example")))
            self.assertEqual(self.response(stream)[0], 403)
            self.assertEqual(stream.read(1), b"")

    def test_authorized_expect_continue_preserves_pipeline(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(headers=("Content-Length: 2", "Expect: 100-continue")))
            self.assertEqual(self.response(stream)[0], 100)
            sock.sendall(b"{}" + self.request("GET", "/api/health", auth=False))
            self.assertEqual(self.response(stream)[0], 404)
            self.assertEqual(self.response(stream)[0], 200)

    def test_short_body_eof_is_400_and_closed(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(headers=("Content-Length: 20",), body=b"{}"))
            sock.shutdown(socket.SHUT_WR)
            status, headers, _ = self.response(stream)
            self.assertEqual(status, 400)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(stream.read(1), b"")

    def test_stalled_body_is_408_and_closed(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(headers=("Content-Length: 20",), body=b"{"))
            status, headers, _ = self.response(stream)
            self.assertEqual(status, 408)
            self.assertEqual(headers.get("connection"), "close")
            self.assertEqual(stream.read(1), b"")

    def test_trickling_body_cannot_extend_total_deadline(self):
        with self.connection() as (sock, stream):
            stop = threading.Event()
            sock.sendall(self.request(headers=("Content-Length: 100",)))

            def trickle():
                while not stop.wait(0.05):
                    try:
                        sock.sendall(b" ")
                    except OSError:
                        return

            writer = threading.Thread(target=trickle, daemon=True)
            writer.start()
            started = time.monotonic()
            try:
                self.assertEqual(self.response(stream)[0], 408)
                self.assertLess(time.monotonic() - started, 1.5)
            finally:
                stop.set()
                writer.join(1)

    def test_unknown_expectation_closes(self):
        self.assert_rejected_and_closed(self.request(headers=("Expect: unexpected",)), 417)

    def test_bad_job_action_path_returns_404(self):
        with self.connection() as (sock, stream):
            sock.sendall(self.request(path="/api/jobs/id/extra/cancel"))
            self.assertEqual(self.response(stream)[0], 404)

    def test_collection_admission_errors_are_json_and_keep_alive(self):
        from raven.api.scheduler import SchedulerStopped, QueueFull
        for exception, expected in ((ValueError, 400), (TypeError, 400),
                                    (SchedulerStopped, 409), (QueueFull, 503)):
            with self.subTest(exception=exception.__name__), \
                    patch.object(server, "submit_collect", side_effect=exception("sensitive input")), \
                    self.connection() as (sock, stream):
                sock.sendall(self.request(path="/api/collect", headers=("Content-Length: 2",), body=b"{}")
                             + self.request("GET", "/api/health", auth=False))
                status, _, body = self.response(stream)
                self.assertEqual(status, expected)
                self.assertIn("error", json.loads(body))
                self.assertNotIn(b"sensitive input", body)
                self.assertEqual(self.response(stream)[0], 200)

    def test_json_recursion_limit_returns_400(self):
        # Decoder recursion thresholds differ between supported Python versions.
        body = b"{}"
        with patch.object(server.json, "loads", side_effect=RecursionError), \
                self.connection() as (sock, stream):
            sock.sendall(self.request(headers=(f"Content-Length: {len(body)}",), body=body))
            self.assertEqual(self.response(stream)[0], 400)

    def test_nonascii_and_duplicate_tokens_are_rejected(self):
        for token_header in (b"X-RAVEN-Token: \xff", ("X-RAVEN-Token: " + server.SESSION_TOKEN
                             + "\r\nX-RAVEN-Token: wrong").encode("ascii")):
            with self.subTest(header=token_header[:20]):
                request = self.request(path="/api/send", auth=False)
                request = request[:-2] + token_header + b"\r\n\r\n"
                self.assert_rejected_and_closed(request, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
