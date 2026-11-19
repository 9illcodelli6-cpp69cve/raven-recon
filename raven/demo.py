from dataclasses import asdict

from .config import Config
from .store import Store


def seed_demo(workspace):
    config = Config("ATLAS / OFFLINE DEMO", ["atlas.test"], ["atlas.test", "*.atlas.test"], ["billing.atlas.test"])
    config.save(workspace)
    store = Store(workspace)
    first = store.start("demo / baseline", asdict(config))
    sample = [
        ("atlas.test", 200, "Atlas — collaboration platform", "cloudflare"),
        ("api.atlas.test", 200, "Atlas API", "envoy"),
        ("admin.staging.atlas.test", 403, "Access restricted", "nginx"),
        ("auth.atlas.test", 302, "Sign in to Atlas", "cloudflare"),
        ("docs.atlas.test", 200, "Atlas developer documentation", "Vercel"),
        ("assets.atlas.test", 200, "", "AmazonS3"),
        ("sandbox.atlas.test", 401, "Sandbox gateway", "nginx"),
        ("upload.atlas.test", 405, "Upload service", "envoy"),
    ]
    for host, status, title, server in sample:
        store.host(host, "demo:certificate", first)
        store.probe(host, {"status": status, "title": title, "server": server,
                          "final_url": "https://" + host + "/", "error": "",
                          "body_hash": "synthetic-v1", "elapsed_ms": 120,
                          "synthetic": True}, first)
    for value in [
        "https://api.atlas.test/v1/users/123?expand=team",
        "https://api.atlas.test/v1/users/456?expand=team",
        "https://api.atlas.test/v1/projects/81/export?format=json",
        "https://auth.atlas.test/oauth/callback?state=DEMO",
        "https://atlas.test/app/main.js",
        "https://api.atlas.test/graphql",
        "https://upload.atlas.test/api/upload",
    ]:
        store.url(value, "demo:archive", first)
    store.finish(first)
    second = store.start("demo / follow-up", asdict(config))
    host = "api.staging.atlas.test"
    store.host(host, "demo:certificate", second)
    store.probe(host, {"status": 200, "title": "Staging API explorer", "server": "uvicorn",
                       "final_url": "https://" + host + "/", "error": "", "body_hash": "synthetic",
                       "elapsed_ms": 84, "synthetic": True}, second)
    store.probe("admin.staging.atlas.test", {"status": 200, "title": "Atlas admin — sign in", "server": "nginx",
                 "final_url": "https://admin.staging.atlas.test/", "error": "", "body_hash": "synthetic-v2",
                 "elapsed_ms": 93, "synthetic": True}, second)
    store.url("https://api.staging.atlas.test/v2/admin/export?workspace=DEMO", "demo:javascript", second,
              {"kind": "fetch", "confidence": "high", "line": 142, "base": "https://api.staging.atlas.test/", "synthetic": True})
    store.finish(second)
    store.close()
    return config

