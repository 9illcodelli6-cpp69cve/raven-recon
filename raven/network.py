import asyncio
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from .analysis import clean, inspect_body
from .scope import canonical_url


class NetworkBlocked(Exception):
    pass


def _is_public_address(value):
    """Require a public unicast address, including for IPv4 mapped into IPv6.

    ``is_global`` alone includes multicast and deprecated IPv6 site-local ranges;
    neither is an acceptable external web destination under the default policy.
    """
    ip = ipaddress.ip_address(value)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (
        ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback
        or ip.is_link_local or getattr(ip, "is_site_local", False)
    )


class ScopedResolver(AbstractResolver):
    """Validate the exact IP addresses supplied to aiohttp's connector."""
    def __init__(self, allow_private=False):
        self.allow_private = allow_private

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        rows = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM, family=family,
        )
        results = []
        for af, _, proto, _, address in rows:
            ip = address[0]
            if not self.allow_private and not _is_public_address(ip):
                raise OSError("Non-public DNS address blocked")
            results.append({"hostname": host, "host": ip, "port": port,
                            "family": af, "proto": proto, "flags": socket.AI_NUMERICHOST})
        return results

    async def close(self):
        pass


class Requester:
    def __init__(self, config, stop: asyncio.Event):
        self.config, self.stop = config, stop
        self.sent = 0
        self.next_slot = 0.0
        self.lock = asyncio.Lock()
        self.blocked_hosts = set()
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=ScopedResolver(self.config.allow_private),
                use_dns_cache=False, force_close=True, limit=self.config.concurrency,
            ),
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
            auto_decompress=False, middlewares=(self._limit,),
        )
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    async def _limit(self, request, handler):
        async with self.lock:
            delay = self.next_slot - time.monotonic()
            while delay > 0 and not self.stop.is_set():
                try:
                    await asyncio.wait_for(self.stop.wait(), timeout=min(delay, 0.2))
                except TimeoutError:
                    pass
                delay = self.next_slot - time.monotonic()
            if self.stop.is_set():
                raise NetworkBlocked("Stopped")
            if request.url.host in self.blocked_hosts:
                raise NetworkBlocked("Host paused after HTTP 429")
            if self.sent >= self.config.max_requests:
                raise NetworkBlocked("Request budget reached")
            self.sent += 1
            self.next_slot = time.monotonic() + 1 / self.config.rate
        return await handler(request)

    async def get(self, url):
        started = time.monotonic()
        chain = []
        result = {"url": url, "status": None, "error": "", "scripts": []}
        body = b""
        try:
            current = canonical_url(url)
            original = urlsplit(current)
            for hop in range(4):
                if not self.config.scope.allows_url(current):
                    raise NetworkBlocked("URL is outside configured scope/ports")
                u = urlsplit(current)
                try:
                    ip = ipaddress.ip_address(u.hostname)
                except ValueError:
                    ip = None
                if ip and not self.config.allow_private and not _is_public_address(ip):
                    raise NetworkBlocked("Non-public IP blocked")
                headers = {"User-Agent": "RavenRecon/0.1 (+authorized-research)",
                           "Accept-Encoding": "identity"}
                # Keep custom headers on their original origin only.
                if (u.scheme, u.netloc) == (original.scheme, original.netloc):
                    headers.update(self.config.headers)
                async with self.session.get(current, headers=headers, allow_redirects=False) as response:
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
                    chunks = bytearray()
                    async for chunk in response.content.iter_chunked(16384):
                        chunks.extend(chunk[:self.config.max_body_bytes + 1 - len(chunks)])
                        if len(chunks) > self.config.max_body_bytes:
                            break
                    body = bytes(chunks[:self.config.max_body_bytes])
                    peer = None
                    if response.connection and response.connection.transport:
                        peer = response.connection.transport.get_extra_info("peername")
                    result.update({
                        "final_url": current, "status": response.status,
                        "server": clean(response_headers.get("server", "")),
                        "content_type": clean(response_headers.get("content-type", "")),
                        "bytes_sampled": len(body), "truncated": len(chunks) > self.config.max_body_bytes,
                        "ip": peer[0] if peer else "", "chain": list(chain),
                    })
                    if response_headers.get("content-encoding", "identity").lower() not in ("identity", ""):
                        body = b""
                        result["body_note"] = "Encoded response skipped (requested identity)"
                    result.update(inspect_body(body, response_headers, current))
                    if response.status == 429:
                        self.blocked_hosts.add(u.hostname)
                        result["body_note"] = "Host paused for this run after 429"
                    location = response_headers.get("location", "")
                    if response.status not in (301, 302, 303, 307, 308) or not location:
                        break
                    try:
                        target = canonical_url(urljoin(current, location))
                    except ValueError:
                        result["redirect_blocked"] = "invalid redirect URL"
                        break
                    if not self.config.scope.allows_url(target):
                        result["redirect_blocked"] = target
                        break
                    if u.scheme == "https" and urlsplit(target).scheme != "https":
                        result["redirect_blocked"] = "HTTPS downgrade: " + target
                        break
                    if target in chain or target == current or hop == 3:
                        result["redirect_blocked"] = "redirect loop or limit"
                        break
                    chain.append(current)
                    current = target
        except NetworkBlocked as exc:
            result["blocked"] = True
            result["error"] = clean(f"{type(exc).__name__}: {exc}", 240)
        except (aiohttp.ClientError, OSError, TimeoutError, ValueError) as exc:
            result["error"] = clean(f"{type(exc).__name__}: {exc}", 240)
            # A redirect may have yielded an HTTP observation before failing.
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result, body
