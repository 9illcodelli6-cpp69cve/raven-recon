"""Strict domain boundaries shared by collectors, imports, and HTTP requests."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


# IDNA2008 / UTS-46 *non-transitional* — what browsers, DNS and crt.sh use. Python's
# built-in "idna" codec is IDNA2003 (transitional): it maps "faß.de" to "fass.de", a
# DIFFERENT registered domain, so a scope rule or an exclude silently pointed at the
# wrong host. Deviation characters are refused if the idna package is unavailable.
try:
    import idna as _idna
except ImportError:  # pragma: no cover - idna ships with the requirements
    _idna = None
_DEVIATIONS = ("\u00df", "\u03c2", "\u200c", "\u200d")


def _to_ascii(value: str) -> str:
    if value.isascii():
        return value
    if _idna is not None:
        try:
            return _idna.encode(value, uts46=True, transitional=False).decode("ascii").lower()
        except (_idna.IDNAError, UnicodeError) as exc:
            raise ValueError(f"Invalid internationalized hostname: {exc}") from None
    if any(c in value for c in _DEVIATIONS):
        raise ValueError("Use the xn-- (A-label) form for this internationalized hostname")
    return value.encode("idna").decode("ascii")


def hostname(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or any(c in value for c in "/\\@%?# \t\r\n"):
        raise ValueError("Expected a hostname or IP, without a URL/path")
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        pass
    value = _to_ascii(value)
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Invalid hostname")
    return value


def rule(value: str) -> str:
    if value.startswith("*."):
        base = hostname(value[2:])
        try:
            ipaddress.ip_address(base)
        except ValueError:
            return "*." + base
        raise ValueError("IP wildcards are unsupported")
    return hostname(value)


def matches(host: str, pattern: str) -> bool:
    return host.endswith("." + pattern[2:]) if pattern.startswith("*.") else host == pattern


def canonical_url(value: str) -> str:
    value = value.strip()
    if len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Unsafe or oversized URL")
    u = urlsplit(value)
    if u.scheme.lower() not in {"http", "https"} or not u.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported")
    if u.username is not None or u.password is not None:
        raise ValueError("Credential-bearing URLs are unsupported")
    host = hostname(u.hostname)
    port = u.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    authority = f"[{host}]" if ":" in host else host
    if port and port != (443 if u.scheme.lower() == "https" else 80):
        authority += f":{port}"
    # Preserve path/query order and repeated parameters; only remove fragments.
    if any(c.isspace() for c in value):
        raise ValueError("URL whitespace must be percent-encoded")
    from urllib.parse import quote
    path = quote(u.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(u.query, safe="/%?:@!$&'()*+,;=-._~[]")
    return urlunsplit((u.scheme.lower(), authority, path, query, ""))


def origin(host: str, scheme: str = "https", port: int | None = None) -> str:
    authority = f"[{host}]" if ":" in host else host
    return canonical_url(f"{scheme}://{authority}{':' + str(port) if port else ''}/")


@dataclass
class Scope:
    include: list[str]
    exclude: list[str]
    ports: list[int]

    def __post_init__(self):
        self.include = [rule(v) for v in self.include]
        self.exclude = [rule(v) for v in self.exclude]
        if not self.include:
            raise ValueError("Scope must have at least one include rule")
        if not self.ports or any(type(p) is not int or not 1 <= p <= 65535 for p in self.ports):
            raise ValueError("ports must contain integers between 1 and 65535")

    def allows_host(self, value: str) -> bool:
        try:
            host = hostname(value)
        except (ValueError, UnicodeError):
            return False
        return any(matches(host, r) for r in self.include) and not any(
            matches(host, r) for r in self.exclude
        )

    def allows_url(self, value: str) -> bool:
        try:
            u = urlsplit(canonical_url(value))
            return self.allows_host(u.hostname or "") and (
                u.port or (443 if u.scheme == "https" else 80)
            ) in self.ports
        except (ValueError, UnicodeError):
            return False

