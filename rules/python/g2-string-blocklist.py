# Semgrep test fixture for mcp-ssrf-audit-g2-python.
# G2: the guard is a string blocklist - the tainted host is compared against
# literals like "localhost"/"127.0.0.1" or internal-suffix strings, with no
# DNS resolution or ipaddress parse in the same function. "127.1",
# decimal/hex/octal IPv4 forms, "::ffff:7f00:1", and "127.0.0.1.nip.io" all
# pass a literal blocklist.

import ipaddress
import socket
from urllib.parse import urlparse

import requests

mcp = None
server = None


# Positive: membership in a literal tuple of internal names/IPs
# (literal-tuple private-name blocklist shape).
@mcp.tool()
async def blocklist_tuple(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g2-python
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: equality against a metadata/internal literal.
@server.call_tool()
async def blocklist_eq(name: str, arguments: dict):
    url = arguments["url"]
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g2-python
    if host == "169.254.169.254" or host == "metadata.google.internal":
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: membership in a named constant with a blocklist-shaped name. The
# rule cannot see the constant's contents; the name is the signal.
@mcp.tool()
async def blocklist_named(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g2-python
    if host.lower() in BLOCKED_HOSTS:
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: internal-suffix string check (endswith(".local")-style). Suffix
# string matching without parsing is still a string blocklist.
@mcp.tool()
async def blocklist_suffix(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g2-python
    if host.endswith(".internal") or host.endswith(".local"):
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: not-in form of the same blocklist.
@mcp.tool()
async def blocklist_not_in(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g2-python
    if host not in ("localhost", "127.0.0.1"):
        return requests.get(url).text
    raise ValueError("blocked")


# Negative: the same literal blocklist plus DNS resolution in the same
# function is not G2 - the resolver call moves it toward a complete guard.
@mcp.tool()
async def blocklist_plus_resolve(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g2-python
    if host in ("localhost", "127.0.0.1"):
        raise ValueError("blocked")
    addr = socket.gethostbyname(host)
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: blocklist plus an ipaddress literal parse in the same function
# is G3-shaped (literal IP check without DNS), not a pure string blocklist.
@mcp.tool()
async def blocklist_plus_ip_parse(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g2-python
    if host in ("localhost", "127.0.0.1"):
        raise ValueError("blocked")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            raise ValueError("blocked")
    except ValueError:
        pass
    return requests.get(url).text


# Negative: membership in a neutral collection is not an internal-host
# blocklist.
@mcp.tool()
async def neutral_membership(url: str) -> str:
    parsed = urlparse(url)
    # ok: mcp-ssrf-audit-g2-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    return requests.get(url).text


# Negative: recognized complete guard; no literal blocklist on the path.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g2-python
    return requests.get(checked).text


# Negative: unrecognized helper guard resolves to the unrecognized state at
# classify time, not G2.
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g2-python
    return requests.get(url).text


# Negative: literal blocklist outside any recognized handler source.
async def helper_blocklist(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g2-python
    if host in ("localhost", "127.0.0.1"):
        raise ValueError("blocked")
    return requests.get(url).text
