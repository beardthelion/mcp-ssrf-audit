# Semgrep test fixture for mcp-ssrf-audit-g1-python.
# G1: the only validation on a model-supplied URL is a scheme check
# (urlparse().scheme in {http, https}) with no host or address check on the
# tainted path. Sinks are .scheme reads on a tainted parse result; functions
# that also resolve the host, parse it as an IP, or feed .hostname/.netloc to
# a check are out of scope (other classes or complete).
#
# The raw G0 rule still fires on the same sites; classify.py relabels the
# site G1 per the layered resolution in docs/source-sink-matrix.md.

import ipaddress
import socket
from urllib.parse import urlparse, urlsplit

import httpx
import requests

mcp = None
server = None


# Positive: fetcher-mcp shape. urlparse().scheme membership check and nothing
# else on the tainted path.
@mcp.tool()
async def fetch_scheme_only(url: str) -> str:
    parsed = urlparse(url)
    # ruleid: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    return requests.get(url).text


# Positive: scheme equality on a direct parse expression (no intermediate
# binding).
@server.call_tool()
async def call_tool_scheme_eq(name: str, arguments: dict):
    url = arguments["url"]
    # ruleid: mcp-ssrf-audit-g1-python
    if urlparse(url).scheme != "https":
        raise ValueError("https only")
    return httpx.get(url).text


# Positive: urlsplit variant and "in" allowlist form.
@mcp.tool()
async def split_scheme(url: str) -> str:
    parts = urlsplit(url)
    # ruleid: mcp-ssrf-audit-g1-python
    if parts.scheme in ("http", "https"):
        return requests.get(url).text
    raise ValueError("bad scheme")


# Positive: scheme check plus a bare hostname-presence check is still
# scheme-only; existence of a host is not host validation (spider_tools
# _validate_url keeps this shape: `if not parsed.hostname: return False`).
@mcp.tool()
async def scheme_and_presence(url: str) -> str:
    parsed = urlparse(url)
    # ruleid: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    if not parsed.hostname:
        raise ValueError("no host")
    return requests.get(url).text


# Negative: scheme check plus a DNS resolution call in the same function is
# not scheme-only (the resolve-and-range-check shape belongs to a complete
# guard or G3 analysis).
@mcp.tool()
async def scheme_plus_resolve(url: str) -> str:
    parsed = urlparse(url)
    # ok: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    addr = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: scheme check plus ipaddress literal parse in the same function
# (no DNS) is G3-shaped, not G1.
@mcp.tool()
async def scheme_plus_ip_parse(url: str) -> str:
    parsed = urlparse(url)
    # ok: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return ""
    if ip.is_loopback:
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: hostname fed to a check call in the same function means the guard
# is more than scheme-only (G2-shaped or helper-based).
@mcp.tool()
async def scheme_plus_host_check(url: str) -> str:
    parsed = urlparse(url)
    # ok: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    if host_is_blocked(parsed.hostname):
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: recognized complete-guard call; the tainted value never reaches a
# scheme read.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g1-python
    return requests.get(checked).text


# Negative: unrecognized helper guard. No scheme read on the tainted path;
# classify.py reports this site as unrecognized-guard, not G1.
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g1-python
    return requests.get(url).text


# Negative: sink outside any recognized handler source.
async def helper_scheme(url: str) -> str:
    parsed = urlparse(url)
    # ok: mcp-ssrf-audit-g1-python
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    return requests.get(url).text
