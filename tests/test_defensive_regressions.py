"""Defensive state/transport regressions. All storage is temporary; no network I/O."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from raven.api import server
from raven.api.scheduler import Scheduler
from raven.scope import Scope


@pytest.fixture(autouse=True)
def isolated_server(tmp_path, monkeypatch):
    saved = dict(server.STATE)
    stores = []
    real_store = server.Store

    def tracked_store(path):
        store = real_store(path)
        stores.append(store)
        return store

    monkeypatch.setattr(server, "DATA_ROOT", tmp_path)
    monkeypatch.setattr(server, "Store", tracked_store)
    monkeypatch.setattr(server, "_ACTIVE_RUNS", {})
    scheduler = Scheduler(workers=1, default_rate=10000)
    monkeypatch.setattr(server, "SCHEDULER", scheduler)
    # A missed mock must fail locally, never resolve an external address.
    monkeypatch.setattr(server.socket, "getaddrinfo", Mock(side_effect=AssertionError("unexpected DNS")))
    context_token = server._REQUEST_CONTEXT.set(None)
    control_token = server._REQUEST_CONTROL.set(None)
    server.STATE.clear()
    server.STATE.update(
        scope=Scope(["alpha.test"], [], [80, 443]), name="alpha", allow_private=False,
        max_body=4096, timeout=1.0, search_headers={}, user_agent_key=server.DEFAULT_UA_KEY,
        user_agent=server.UA_CATALOG[server.DEFAULT_UA_KEY][1],
    )
    server.use_workspace("alpha")
    try:
        yield SimpleNamespace(root=tmp_path, workspace=tmp_path / "workspaces" / "alpha")
    finally:
        scheduler.shutdown()
        for store in stores:
            store.close()
        server._REQUEST_CONTROL.reset(control_token)
        server._REQUEST_CONTEXT.reset(context_token)
        server.STATE.clear()
        server.STATE.update(saved)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def configure_identity():
    return server.set_identity({
        "search_headers": {"X-Request-Purpose": "Research", "X-Local-Label": "alpha"},
        "user_agent_key": "custom", "user_agent_custom": "Local compatibility fixture/1",
    })


def test_identity_partial_update_keeps_headers_and_custom_ua(isolated_server):
    original = configure_identity()
    updated = server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
    assert updated["user_agent"] == original["user_agent"]
    selected = server.set_identity({"user_agent_key": "firefox-windows"})
    assert selected["search_headers"] == {"X-Request-Purpose": "Research"}
    saved = read_json(isolated_server.workspace / "identity.json")
    assert saved["search_headers"] == selected["search_headers"]
    assert saved["user_agent"] == server.UA_CATALOG["firefox-windows"][1]


def test_identity_write_failure_preserves_memory_file_and_removes_temp(isolated_server, monkeypatch):
    configure_identity()
    before = server.identity_dict()
    identity_path = isolated_server.workspace / "identity.json"
    old_bytes = identity_path.read_bytes()
    replace = server.os.replace

    def fail_identity_publish(source, destination):
        if Path(destination) == identity_path:
            raise OSError("local fixture: publication failed")
        return replace(source, destination)

    monkeypatch.setattr(server.os, "replace", fail_identity_publish)
    with pytest.raises(OSError):
        server.set_identity({"user_agent_key": "firefox-linux"})
    assert server.identity_dict() == before
    assert identity_path.read_bytes() == old_bytes
    assert list(isolated_server.workspace.glob("identity.json.*.tmp")) == []


def test_invalid_identity_update_does_not_apply_valid_partial_fields(isolated_server):
    configure_identity()
    before = server.identity_dict()
    saved = (isolated_server.workspace / "identity.json").read_bytes()
    with pytest.raises(ValueError):
        server.set_identity({"search_headers": {"X-Local-Label": "changed"},
                             "user_agent_key": "unknown-profile"})
    assert server.identity_dict() == before
    assert (isolated_server.workspace / "identity.json").read_bytes() == saved


def mock_connection(monkeypatch):
    response = SimpleNamespace(status=200, reason="OK", read=lambda limit: b"local fixture",
                               getheaders=lambda: [("Content-Type", "text/plain")])
    connection = Mock()
    connection.getresponse.return_value = response
    monkeypatch.setattr(server, "_pick_public_ip", Mock(return_value="127.0.0.1"))
    monkeypatch.setattr(server, "_PinnedHTTPConnection", Mock(return_value=connection))
    return connection


def test_sender_dedupes_headers_and_enforces_selected_ua_and_framing(monkeypatch):
    identity = configure_identity()
    connection = mock_connection(monkeypatch)
    result = server.do_send({"url": "http://alpha.test/", "method": "POST", "body": "abc", "headers": {
        "X-Request-Purpose": "wrong-upper", "x-request-purpose": "wrong-lower",
        "User-Agent": "wrong-upper", "USER-AGENT": "wrong-lower", "Cookie": "fixture-only",
        "HOST": "ignored.invalid", "Content-Length": "999", "Transfer-Encoding": "chunked",
        "Connection": "keep-alive", "Accept-Encoding": "gzip", "Proxy-Authorization": "fixture-only",
        "X-RAVEN-Token": "fixture-only", "X-Optional": "first", "x-optional": "last",
    }})
    assert result.get("ok"), result
    headers = connection.request.call_args.kwargs["headers"]
    lowered = {name.lower(): value for name, value in headers.items()}
    assert len(lowered) == len(headers)
    assert lowered["x-request-purpose"] == "Research"
    assert lowered["user-agent"] == identity["user_agent"]
    assert lowered["x-optional"] == "last"
    assert lowered["cookie"] == "fixture-only"
    assert lowered["connection"] == "close" and lowered["accept-encoding"] == "identity"
    assert not {"host", "content-length", "transfer-encoding", "proxy-authorization", "x-raven-token"} & lowered.keys()
    assert connection.request.call_args.kwargs["body"] == b"abc"
    connection.close.assert_called_once()
    assert server.SCHEDULER._inflight == {}


@pytest.mark.parametrize("body", [[], {}, 0, False, None])
def test_sender_rejects_non_string_body_before_dns(body):
    result = server.do_send({"url": "http://alpha.test/", "method": "POST", "body": body})
    assert result.get("blocked") and "body" in result["error"]
    server.socket.getaddrinfo.assert_not_called()


@pytest.mark.parametrize("headers", [[], False, 0, ["bad"], {"X-Test": "line\nvalue"}])
def test_sender_rejects_invalid_header_shapes_without_dispatch(headers, monkeypatch):
    connection = mock_connection(monkeypatch)
    result = server.do_send({"url": "http://alpha.test/", "headers": headers})
    assert result.get("blocked"), result
    connection.request.assert_not_called()


def test_workspace_conflict_preserves_store_scope_identity_and_pointer(isolated_server):
    configure_identity()
    before = dict(server.STATE)
    scope_bytes = (isolated_server.workspace / "scope.json").read_bytes()
    pointer_bytes = (isolated_server.root / "active-workspace.json").read_bytes()
    assets = before["store"].assets()
    with pytest.raises(ValueError):
        server.set_scope({"name": "alpha", "include": ["beta.test"], "ports": [80]})
    assert server.STATE == before
    assert before["store"].assets() == assets
    assert (isolated_server.workspace / "scope.json").read_bytes() == scope_bytes
    assert (isolated_server.root / "active-workspace.json").read_bytes() == pointer_bytes


def test_workspace_database_without_scope_marker_is_preserved(isolated_server):
    destination = isolated_server.root / "workspaces" / "beta"
    destination.mkdir()
    database = destination / "recon.db"
    database.write_bytes(b"unowned local fixture: preserve verbatim")
    before = dict(server.STATE)
    with pytest.raises(ValueError):
        server.set_scope({"name": "beta", "include": ["beta.test"]})
    assert server.STATE == before
    assert database.read_bytes() == b"unowned local fixture: preserve verbatim"
    assert not (destination / "scope.json").exists()


@pytest.mark.parametrize("contents", ["not json", "[]", '{"include": "beta.test"}'])
def test_corrupt_scope_marker_is_preserved_and_does_not_switch(isolated_server, contents):
    destination = isolated_server.root / "workspaces" / "beta"
    destination.mkdir()
    marker = destination / "scope.json"
    marker.write_text(contents, encoding="utf-8")
    before = dict(server.STATE)
    with pytest.raises(ValueError):
        server.set_scope({"name": "beta", "include": ["beta.test"]})
    assert server.STATE == before
    assert marker.read_text(encoding="utf-8") == contents
    assert not (destination / "recon.db").exists()


@pytest.mark.parametrize("contents", ["not json", "[]", '{"search_headers":{"X-Test":"valid"},"user_agent_key":"unknown"}'])
def test_corrupt_identity_does_not_partially_replace_current_state(isolated_server, contents):
    configure_identity()
    destination = isolated_server.root / "workspaces" / "beta"
    destination.mkdir()
    (destination / "scope.json").write_text(json.dumps({"include": ["beta.test"]}), encoding="utf-8")
    identity = destination / "identity.json"
    identity.write_text(contents, encoding="utf-8")
    before = dict(server.STATE)
    with pytest.raises(ValueError):
        server.set_scope({"name": "beta", "include": ["beta.test"]})
    assert server.STATE == before
    assert identity.read_text(encoding="utf-8") == contents
    assert not (destination / "recon.db").exists()


def test_restore_active_workspace_recovers_exact_scope_and_identity(isolated_server):
    server.set_scope({"name": "beta", "include": ["beta.test"], "exclude": ["blocked.beta.test"],
                      "ports": [8443], "allow_private": False})
    expected_identity = configure_identity()
    server.STATE.update(name="startup", scope=Scope(["startup.test"], [], [80]), search_headers={})
    server.STATE.pop("store", None)
    server.STATE.pop("ws_dir", None)
    server._restore_workspace()
    assert server.STATE["name"] == "beta"
    assert server.STATE["scope"] == Scope(["beta.test"], ["blocked.beta.test"], [8443])
    assert server.identity_dict() == expected_identity
    assert not server.STATE.get("configuration_error")
    assert server.STATE["store"].assets()[0]["host"] == "beta.test"


@pytest.mark.parametrize("contents", ["not json", "[]", '{"name": null}', '{"name": "missing"}'])
def test_invalid_active_pointer_blocks_sending_without_dns(isolated_server, contents):
    pointer = isolated_server.root / "active-workspace.json"
    pointer.write_text(contents, encoding="utf-8")
    server._restore_workspace()
    assert server.STATE.get("configuration_error")
    result = server.do_send({"url": "http://alpha.test/"})
    assert result.get("blocked")
    assert pointer.read_text(encoding="utf-8") == contents
    server.socket.getaddrinfo.assert_not_called()


def test_scope_persistence_failure_rolls_back_state_and_pointer(isolated_server, monkeypatch):
    before = dict(server.STATE)
    pointer = (isolated_server.root / "active-workspace.json").read_bytes()
    publish = server._atomic_json

    def fail_scope(path, value):
        if Path(path).name == "scope.json":
            raise OSError("local fixture: scope write failed")
        return publish(path, value)

    monkeypatch.setattr(server, "_atomic_json", fail_scope)
    with pytest.raises(OSError):
        server.set_scope({"name": "beta", "include": ["beta.test"]})
    assert server.STATE == before
    assert (isolated_server.root / "active-workspace.json").read_bytes() == pointer


def test_pointer_publish_failure_restores_previous_scope_file(isolated_server, monkeypatch):
    before = dict(server.STATE)
    marker = isolated_server.workspace / "scope.json"
    saved_scope = read_json(marker)
    publish = server._atomic_json

    def fail_pointer(path, value):
        if Path(path).name == "active-workspace.json":
            raise OSError("local fixture: pointer write failed")
        return publish(path, value)

    monkeypatch.setattr(server, "_atomic_json", fail_pointer)
    with pytest.raises(OSError):
        server.set_scope({"name": "alpha", "include": ["alpha.test"], "exclude": ["blocked.alpha.test"]})
    assert server.STATE == before
    assert read_json(marker) == saved_scope


def test_failed_scope_rollback_keeps_configuration_blocked(isolated_server, monkeypatch):
    publish = server._atomic_json
    scope_writes = []

    def fail_pointer_and_rollback(path, value):
        if Path(path).name == "active-workspace.json":
            raise OSError("local fixture: pointer write failed")
        if Path(path).name == "scope.json":
            scope_writes.append(value)
            if len(scope_writes) > 1:
                raise OSError("local fixture: rollback write failed")
        return publish(path, value)

    monkeypatch.setattr(server, "_atomic_json", fail_pointer_and_rollback)
    with pytest.raises(OSError):
        server.set_scope({"name": "alpha", "include": ["alpha.test"], "exclude": ["blocked.alpha.test"]})
    assert server.STATE.get("configuration_error"), "failed rollback must not clear the send block"
    result = server.do_send({"url": "http://alpha.test/"})
    assert result.get("blocked")
    server.socket.getaddrinfo.assert_not_called()


@pytest.mark.parametrize("flag", ["false", "true", 0, 1, [], {}, None])
def test_allow_private_requires_a_boolean_before_state_change(flag):
    before = dict(server.STATE)
    with pytest.raises(ValueError):
        server.set_scope({"name": "alpha", "include": ["alpha.test"], "allow_private": flag})
    assert server.STATE == before


def test_acl_keeps_one_context_despite_global_workspace_change(monkeypatch, isolated_server):
    configure_identity()
    initial = server._capture_context()
    observed = []

    def fake_send(payload):
        observed.append(server._request_context())
        if len(observed) == 1:
            server.STATE.update(name="beta", ws_dir=isolated_server.root / "workspaces" / "beta",
                                scope=Scope(["beta.test"], [], [80]), search_headers={"X-Local-Label": "beta"},
                                user_agent="Different local fixture/2")
        return {"ok": True, "status": 200, "headers": {}, "body": "fixture", "bytes": 7}

    monkeypatch.setattr(server, "do_send", fake_send)
    result = server.do_access_check({"url": "http://alpha.test/", "sessions": [{"label": "A"}, {"label": "B"}],
                                     "anonymous_baseline": True})
    assert len(result["results"]) == 3
    assert observed == [initial, initial, initial]
    assert server.STATE["name"] == "beta"
    assert server._REQUEST_CONTEXT.get() is None


@pytest.mark.parametrize("invalid_session", [1, [], {"headers": ["wrong"]}, {"headers": []},
    {"headers": False}, {"cookies": 123}, {"cookies": "line\nvalue"}, {"expected": "maybe"},
    {"headers": {"X-Test": "\u2603"}}, {"headers": {"X-Test": "line\rvalue"}},
])
def test_acl_validates_every_identity_before_first_send(invalid_session, monkeypatch):
    send = Mock(side_effect=AssertionError("must validate all identities before sending"))
    monkeypatch.setattr(server, "do_send", send)
    result = server.do_access_check({"url": "http://alpha.test/", "sessions": [{"label": "valid"}, invalid_session]})
    assert result.get("error"), result
    send.assert_not_called()


@pytest.mark.parametrize("body", [[], {}, 0, False])
def test_acl_rejects_non_string_body_before_send(body, monkeypatch):
    send = Mock(side_effect=AssertionError("must reject invalid body before sending"))
    monkeypatch.setattr(server, "do_send", send)
    result = server.do_access_check({"url": "http://alpha.test/", "sessions": [{}], "body": body})
    assert result.get("error"), result
    send.assert_not_called()


@pytest.mark.parametrize("consent", ["false", "true", 1, 0, [], {}, None, False])
def test_acl_state_changing_consent_is_strict(consent, monkeypatch):
    send = Mock(side_effect=AssertionError("no explicit boolean consent"))
    monkeypatch.setattr(server, "do_send", send)
    result = server.do_access_check({"url": "http://alpha.test/", "method": "POST", "sessions": [{}],
                                     "confirm_state_changing": consent})
    assert result.get("refused"), result
    send.assert_not_called()


def test_configuration_error_blocks_collection_before_any_work(monkeypatch):
    server.STATE["configuration_error"] = "local fixture: invalid saved settings"
    start = Mock(side_effect=AssertionError("no run should start"))
    passive = Mock(side_effect=AssertionError("no passive lookup should start"))
    monkeypatch.setattr(server.STATE["store"], "start", start)
    monkeypatch.setattr(server, "_passive_crtsh", passive)
    with pytest.raises(ValueError, match="invalid saved settings"):
        server.do_collect(passive=True, probe=True)
    start.assert_not_called()
    passive.assert_not_called()


def test_stop_resume_during_dns_does_not_revive_prepared_request(monkeypatch):
    def resolve(_host):
        server.SCHEDULER.emergency_stop()
        server.SCHEDULER.clear_stop()
        return "93.184.216.34"

    monkeypatch.setattr(server, "_pick_public_ip", resolve)
    connection = Mock()
    monkeypatch.setattr(server, "_PinnedHTTPConnection", Mock(return_value=connection))
    result = server.do_send({"url": "http://alpha.test/"})
    assert result.get("blocked"), result
    connection.request.assert_not_called()


def test_import_preserves_captured_scope_store_across_switch(monkeypatch):
    old_store = server.STATE["store"]
    real_host = old_store.host

    def switch_after_first(value, source, run_id):
        result = real_host(value, source, run_id)
        server.set_scope({"name": "beta", "include": ["beta.test"], "ports": [80]})
        return result

    monkeypatch.setattr(old_store, "host", switch_after_first)
    result = server.do_import(["alpha.test", "beta.test"])
    assert result["assets"] == 1
    assert {item["host"] for item in old_store.assets()} == {"alpha.test"}
    assert {item["host"] for item in server.STATE["store"].assets()} == {"beta.test"}
    assert not server._ACTIVE_RUNS


@pytest.mark.parametrize("items", [None, "alpha.test", {}, [1]])
def test_import_rejects_invalid_input_before_start(items, monkeypatch):
    start = Mock(side_effect=AssertionError("invalid input must not create a run"))
    monkeypatch.setattr(server.STATE["store"], "start", start)
    with pytest.raises(ValueError, match="list of strings"):
        server.do_import(items)
    start.assert_not_called()


def test_missing_active_pointer_with_corrupt_default_keeps_recovery_ui_available(isolated_server):
    (isolated_server.root / "active-workspace.json").unlink()
    (isolated_server.workspace / "scope.json").write_text("invalid saved JSON", encoding="utf-8")
    server._restore_workspace()
    assert server.STATE.get("configuration_error")
    assert server.do_send({"url": "http://alpha.test/"}).get("blocked")
