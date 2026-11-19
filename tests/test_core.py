import json
from dataclasses import asdict

import pytest

from raven.analysis import family, js_endpoints, clean, priority
from raven.config import Config
from raven.engine import Engine, workspace_lock
from raven.export import export_report
from raven.scope import Scope, canonical_url
from raven.store import Store


@pytest.fixture
def scope():
    return Scope(["example.com", "*.example.com"], ["billing.example.com", "*.private.example.com"], [80, 443])


@pytest.mark.parametrize("url", [
    "https://example.com.evil.test/", "https://evil-example.com/", "https://example.com@evil.test/",
    "https://billing.example.com/", "https://x.private.example.com/", "https://example.com:8443/",
    "file:///etc/passwd", "javascript:alert(1)", "https://example.com\\@evil.test/",
    "https://example.com/%0d%0a",  # Encoded path characters are not a host bypass; tested separately below.
])
def test_scope_boundaries(scope, url):
    if url.endswith("/%0d%0a"):
        assert scope.allows_url(url)
    else:
        assert not scope.allows_url(url)


def test_scope_wildcard_apex_and_normalization(scope):
    wildcard = Scope(["*.example.com"], [], [443])
    assert not wildcard.allows_host("example.com")
    assert wildcard.allows_host("a.b.example.com")
    assert scope.allows_url("https://API.EXAMPLE.COM.:443/a?id=1&id=2#frag")
    assert canonical_url("https://API.EXAMPLE.COM.:443/a?id=1&id=2#frag") == "https://api.example.com/a?id=1&id=2"
    assert canonical_url("https://example.com/search?q=a+b&q=a%20b").endswith("?q=a+b&q=a%20b")
    assert Scope(["bücher.example"], [], [443]).allows_url("https://xn--bcher-kva.example/")


def test_js_keeps_evidence_filters_dynamic_and_clusters():
    text = '''fetch('/api/items/12?id=1');
axios.get('/api/items/44?id=2');
fetch(`/api/${computed}`);
fetch('/api/items/12?id=1');'''
    endpoints = list(js_endpoints(text, "https://app.example.com/dashboard/"))
    assert len(endpoints) == 2
    assert endpoints[0]["kind"] == "fetch" and endpoints[0]["line"] == 1
    assert endpoints[1]["line"] == 2
    assert family(endpoints[0]["url"]) == family(endpoints[1]["url"])
    assert clean("x\x1b[31mred\x1b[0m\x07") == "xred"


def test_tld_is_not_mistaken_for_staging_signal():
    assert priority("https://example.test/")[0] == 0
    assert "non-production naming" not in priority("https://api.example.dev/")[1]
    assert "non-production naming" in priority("https://staging.example.com/")[1]


def test_import_delta_scope_narrowing_and_export(tmp_path):
    config = Config("Test", ["example.com"], ["example.com", "*.example.com"])
    config.save(tmp_path)
    store = Store(tmp_path)
    source = tmp_path / "input.txt"
    source.write_text('api.example.com\napi.example.com\nhttps://api.example.com/v1/12?id=1\n'
                      '{"url":"https://api.example.com/v1/44?id=2"}\noutside.test\n')
    first = Engine(config, store)
    first.import_file(source)
    assert first.rejected == 1
    assert len(store.assets()) == 1 and len(store.urls()) == 2
    initial_changes = len(store.changes())
    Engine(config, store).import_file(source)
    assert len(store.changes()) == initial_changes
    run = store.start("http", asdict(config))
    store.probe("api.example.com", {"status": 403, "title": "Restricted", "error": ""}, run)
    store.finish(run)
    run = store.start("http", asdict(config))
    store.probe("api.example.com", {"status": 200, "title": "Login", "error": ""}, run)
    store.finish(run)
    assert store.changes()[0]["detail"] == "status, title"
    assert store.assets()[0]["probe"]["status"] == 200
    exported = export_report(store, config)
    report = json.loads((exported / "report.json").read_text())
    assert len(report["urls"]) == 2
    config.exclude = ["api.example.com"]
    report = json.loads((export_report(store, config) / "report.json").read_text())
    assert report["assets"] == [] and report["urls"] == [] and report["changes"] == []
    store.close()


def test_existing_config_is_not_overwritten_and_lock_excludes_writers(tmp_path):
    config = Config("Test", ["example.com"], ["example.com"])
    config.save(tmp_path)
    with pytest.raises(FileExistsError):
        config.save(tmp_path)
    with workspace_lock(tmp_path):
        with pytest.raises(ValueError, match="Another operation"):
            with workspace_lock(tmp_path):
                pass


@pytest.mark.parametrize("field,value", [("rate", 0), ("rate", float("nan")), ("concurrency", 0),
                                        ("max_requests", -1), ("headers", {"Host": "elsewhere"}),
                                        ("headers", {"X-Researcher": "a\r\nb"})])
def test_invalid_limits_rejected(field, value):
    config = Config("Test", ["example.com"], ["example.com"])
    setattr(config, field, value)
    with pytest.raises(ValueError):
        config.validate()
