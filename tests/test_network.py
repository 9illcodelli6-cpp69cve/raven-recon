import asyncio
import socket
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from raven.config import Config
from raven.network import Requester, ScopedResolver, _is_public_address


@asynccontextmanager
async def server(handler):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        await runner.cleanup()


def config_for(port, **options):
    return Config("Local", ["127.0.0.1"], ["127.0.0.1"], ports=[port],
                  allow_private=True, rate=50, **options).validate()


async def test_redirect_leaves_scope_without_contacting_destination():
    hits = []

    async def handler(req):
        hits.append(req.path)
        return web.Response(status=302, headers={"Location": "http://outside.invalid/private"})

    async with server(handler) as port:
        async with Requester(config_for(port), asyncio.Event()) as client:
            data, _ = await client.get(f"http://127.0.0.1:{port}/")
            assert data["status"] == 302
            assert data["redirect_blocked"] == "http://outside.invalid/private"
            assert client.sent == 1 and hits == ["/"]


async def test_relative_redirect_and_bounded_body():
    async def handler(req):
        if req.path == "/":
            return web.Response(status=302, headers={"Location": "/app"})
        return web.Response(text='<html><title>Local test</title><script src="/main.js"></script>' + "x" * 3000,
                            content_type="text/html")

    async with server(handler) as port:
        async with Requester(config_for(port, max_body_bytes=1024), asyncio.Event()) as client:
            data, body = await client.get(f"http://127.0.0.1:{port}/")
            assert data["title"] == "Local test" and data["status"] == 200
            assert data["truncated"] and len(body) == 1024
            assert data["scripts"] == [f"http://127.0.0.1:{port}/main.js"]
            assert client.sent == 2


async def test_budget_and_cancellation_prevent_new_requests():
    hits = []

    async def handler(req):
        hits.append(req.path)
        return web.Response(text="ok")

    async with server(handler) as port:
        stop = asyncio.Event()
        async with Requester(config_for(port, max_requests=2), stop) as client:
            url = f"http://127.0.0.1:{port}/"
            assert (await client.get(url))[0]["status"] == 200
            assert (await client.get(url))[0]["status"] == 200
            assert "budget" in (await client.get(url))[0]["error"]
            stop.set()
            assert "Stopped" in (await client.get(url))[0]["error"]
            assert len(hits) == 2


async def test_429_pauses_host_for_rest_of_run():
    hits = []

    async def handler(req):
        hits.append(req.path)
        return web.Response(status=429)

    async with server(handler) as port:
        async with Requester(config_for(port), asyncio.Event()) as client:
            url = f"http://127.0.0.1:{port}/"
            assert (await client.get(url))[0]["status"] == 429
            assert "paused" in (await client.get(url))[0]["error"]
            assert len(hits) == 1


async def test_private_ip_and_dns_are_blocked_before_request(monkeypatch):
    config = Config("Local", ["127.0.0.1"], ["127.0.0.1"])
    async with Requester(config, asyncio.Event()) as client:
        data, _ = await client.get("http://127.0.0.1/")
        assert "Non-public" in data["error"] and client.sent == 0

    async def fake_lookup(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_lookup)
    with pytest.raises(OSError, match="Non-public DNS"):
        await ScopedResolver().resolve("public-looking.example", 80)


@pytest.mark.parametrize("address", [
    "100.64.0.1", "100.127.255.254", "224.0.0.1", "239.255.255.250",
    "fec0::1", "ff02::1", "::ffff:100.64.0.1", "::ffff:224.0.0.1",
])
async def test_non_public_unicast_policy_blocks_literal_and_dns_without_network(address, monkeypatch):
    assert not _is_public_address(address)
    config = Config("Local", [address], [address]).validate()
    client = Requester(config, asyncio.Event())
    # No session is opened: accepting this address would fail before any real I/O.
    authority = f"[{address}]" if ":" in address else address
    data, _ = await client.get(f"http://{authority}/")
    assert data.get("blocked") and "Non-public" in data["error"]
    assert client.sent == 0

    async def fake_lookup(*args, **kwargs):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
            (family, socket.SOCK_STREAM, 6, "", (address, 80)),
        ]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_lookup)
    with pytest.raises(OSError, match="Non-public DNS"):
        await ScopedResolver().resolve("local-test.invalid", 80)


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_unicast_address_classification(address):
    # Classification only; these addresses are never contacted by this test.
    assert _is_public_address(address)


async def test_global_rate_applies_across_concurrent_calls():
    seen = []

    async def handler(req):
        seen.append(time.monotonic())
        return web.Response(text="ok")

    async with server(handler) as port:
        config = config_for(port)
        config.rate = 10
        async with Requester(config, asyncio.Event()) as client:
            await asyncio.gather(*(client.get(f"http://127.0.0.1:{port}/{i}") for i in range(3)))
        assert len(seen) == 3
        assert min(b - a for a, b in zip(seen, seen[1:])) >= 0.075


async def test_total_request_timeout():
    async def handler(req):
        await asyncio.sleep(1.25)
        return web.Response(text="late")

    async with server(handler) as port:
        async with Requester(config_for(port, timeout=1), asyncio.Event()) as client:
            data, _ = await client.get(f"http://127.0.0.1:{port}/")
            assert "Timeout" in data["error"]

