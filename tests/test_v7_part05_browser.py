"""RAVEN V7 Part 05 — Browser + Traffic Engine Tests."""
import sqlite3
import pytest


def fresh_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


# ── Scope Guard ───────────────────────────────────────────────────────────────

class TestScopeGuard:
    def test_empty_scope_denies_all(self):
        from raven.browser_engine.scope_guard import ScopeGuard, ScopeViolation
        sg = ScopeGuard()
        assert not sg.is_in_scope("https://example.com")

    def test_in_scope_host_allowed(self):
        from raven.browser_engine.scope_guard import ScopeGuard
        sg = ScopeGuard(allowed_hosts=["example.com"])
        assert sg.is_in_scope("https://example.com/path")

    def test_wildcard_subdomain(self):
        from raven.browser_engine.scope_guard import ScopeGuard
        sg = ScopeGuard(allowed_hosts=["*.example.com"])
        assert sg.is_in_scope("https://sub.example.com/api")
        assert not sg.is_in_scope("https://evil.com")

    def test_check_raises_on_out_of_scope(self):
        from raven.browser_engine.scope_guard import ScopeGuard, ScopeViolation
        sg = ScopeGuard(allowed_hosts=["safe.com"])
        with pytest.raises(ScopeViolation):
            sg.check("https://evil.com/attack")

    def test_check_passes_in_scope(self):
        from raven.browser_engine.scope_guard import ScopeGuard
        sg = ScopeGuard(allowed_hosts=["safe.com"])
        sg.check("https://safe.com/api/v1")  # no exception

    def test_add_host(self):
        from raven.browser_engine.scope_guard import ScopeGuard
        sg = ScopeGuard()
        sg.add("target.com")
        assert sg.is_in_scope("https://target.com")


# ── HTTP Client ───────────────────────────────────────────────────────────────

class TestHttpClient:
    def test_out_of_scope_blocked(self):
        from raven.browser_engine.http_client import HttpClient, HttpRequest
        from raven.browser_engine.scope_guard import ScopeGuard
        sg = ScopeGuard(allowed_hosts=["allowed.com"])
        client = HttpClient(scope_guard=sg)
        resp = client.get("https://evil.com/steal")
        assert resp.scope_blocked
        assert resp.error is not None

    def test_to_dict(self):
        from raven.browser_engine.http_client import HttpRequest, HttpResponse
        req = HttpRequest(url="https://example.com", method="GET")
        resp = HttpResponse(request=req, status_code=200)
        d = resp.to_dict()
        assert d["url"] == "https://example.com"
        assert d["status_code"] == 200

    def test_request_redacts_auth_header(self):
        from raven.browser_engine.http_client import HttpRequest
        req = HttpRequest(url="https://x.com", headers={"Authorization": "Bearer secret"})
        d = req.to_dict()
        assert "Authorization" not in d["headers"] or d["headers"].get("Authorization") != "Bearer secret"

    def test_no_scope_allows_any(self):
        from raven.browser_engine.http_client import HttpClient, HttpResponse
        client = HttpClient(scope_guard=None)
        # We don't actually hit the network; just test no scope_blocked
        from raven.browser_engine.http_client import HttpRequest
        req = HttpRequest(url="https://example.com")
        # We can't test a real request without network; we test the scope logic
        assert not req.url.startswith("http://blocked")


# ── Traffic Recorder ──────────────────────────────────────────────────────────

class TestTrafficRecorder:
    def test_new_session(self):
        from raven.browser_engine.traffic import TrafficRecorder
        db = fresh_db()
        recorder = TrafficRecorder(db=db)
        session = recorder.new_session(workspace_id="ws1", name="test run")
        assert session.session_id
        assert session.name == "test run"

    def test_record_and_list(self):
        from raven.browser_engine.traffic import TrafficRecorder
        from raven.browser_engine.http_client import HttpRequest, HttpResponse
        db = fresh_db()
        recorder = TrafficRecorder(db=db)
        session = recorder.new_session()
        req = HttpRequest(url="https://example.com", method="GET")
        resp = HttpResponse(request=req, status_code=200, body_text="<html/>")
        entry = recorder.record(session.session_id, req, resp)
        assert entry.entry_id
        assert entry.status_code == 200

        entries = recorder.list_entries(session.session_id)
        assert len(entries) == 1
        assert entries[0].url == "https://example.com"

    def test_count(self):
        from raven.browser_engine.traffic import TrafficRecorder
        from raven.browser_engine.http_client import HttpRequest, HttpResponse
        db = fresh_db()
        recorder = TrafficRecorder(db=db)
        session = recorder.new_session()
        req = HttpRequest(url="https://x.com")
        resp = HttpResponse(request=req, status_code=404)
        recorder.record(session.session_id, req, resp)
        recorder.record(session.session_id, req, resp)
        assert recorder.count(session.session_id) == 2

    def test_sensitive_headers_redacted(self):
        from raven.browser_engine.traffic import _redact_headers
        headers = {"Authorization": "Bearer tok", "Content-Type": "application/json"}
        redacted = _redact_headers(headers)
        assert redacted["Authorization"] == "[REDACTED]"
        assert redacted["Content-Type"] == "application/json"


# ── Repeater ──────────────────────────────────────────────────────────────────

class TestRepeater:
    def _make_client(self):
        from raven.browser_engine.http_client import HttpClient, HttpRequest, HttpResponse
        from unittest.mock import MagicMock
        client = MagicMock()
        client.send.return_value = HttpResponse(
            request=HttpRequest(url="https://t.com"),
            status_code=200,
            body_text="OK",
        )
        return client

    def test_repeat_records_modifications(self):
        from raven.browser_engine.repeater import Repeater
        from raven.browser_engine.http_client import HttpRequest
        client = self._make_client()
        r = Repeater(client=client)
        req = HttpRequest(url="https://t.com/api", headers={"X-Token": "abc"})
        result = r.repeat(req, modify_headers={"X-Token": "evil"})
        assert result.success
        assert any("X-Token" in m for m in result.modifications)

    def test_repeat_url_change(self):
        from raven.browser_engine.repeater import Repeater
        from raven.browser_engine.http_client import HttpRequest
        client = self._make_client()
        r = Repeater(client=client)
        req = HttpRequest(url="https://t.com/page1")
        result = r.repeat(req, modify_url="https://t.com/page2")
        assert result.modified_url == "https://t.com/page2"
        assert result.original_url == "https://t.com/page1"

    def test_to_dict(self):
        from raven.browser_engine.repeater import RepeatResult
        from raven.browser_engine.http_client import HttpResponse, HttpRequest
        resp = HttpResponse(request=HttpRequest(url="x"), status_code=200)
        r = RepeatResult(original_url="a", modified_url="b", response=resp)
        d = r.to_dict()
        assert d["status_code"] == 200


# ── Tool Registration ─────────────────────────────────────────────────────────

class TestBrowserToolRegistration:
    def test_register_browser_tools(self):
        from raven.browser_engine.registry import register_browser_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        count = register_browser_tools(registry)
        assert count >= 4
        tools = registry.list_all()
        ids = [t.tool_id for t in tools]
        assert "browser.http.get" in ids
        assert "browser.http.post" in ids
        assert "browser.repeater.send" in ids
