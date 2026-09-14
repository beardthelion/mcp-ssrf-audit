# Semgrep test fixture for mcp-ssrf-audit-g5-python.
# G5: the guard handles IPv6 textually and incompletely - a startswith or
# substring check for the "::ffff:" mapped prefix instead of parsing the
# address. The URL parser normalizes ::ffff:a.b.c.d to hextets
# (::ffff:7f00:1) and the textual probe misses 6to4, Teredo, and
# case/bracket variants.

import ipaddress
from urllib.parse import urlparse

import requests

mcp = None
server = None


# Positive: auth-fetch-mcp shape - textual ::ffff: prefix check on the
# tainted host.
@mcp.tool()
async def mapped_prefix(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g5-python
    if host.startswith("::ffff:"):
        raise ValueError("mapped address blocked")
    return requests.get(url).text


# Positive: substring form of the same partial normalization.
@server.call_tool()
async def mapped_substring(name: str, arguments: dict):
    url = arguments["url"]
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g5-python
    if "::ffff:" in host:
        raise ValueError("mapped address blocked")
    return requests.get(url).text


# Positive: bracketed literal variant and removeprefix rewrite of the
# tainted host.
@mcp.tool()
async def mapped_bracket(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g5-python
    if host.startswith("[::ffff:"):
        raise ValueError("mapped address blocked")
    # ruleid: mcp-ssrf-audit-g5-python
    stripped = host.removeprefix("::ffff:")
    if stripped:
        pass
    return requests.get(url).text


# Positive: textual replace of the mapped prefix on the tainted host.
@mcp.tool()
async def mapped_replace(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g5-python
    v4 = host.replace("::ffff:", "")
    if v4.startswith("127."):
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: parsing the address and checking .ipv4_mapped is normalization
# through the parser, not a textual prefix probe.
@mcp.tool()
async def parsed_mapped(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g5-python
    ip = ipaddress.ip_address(host.strip("[]"))
    if getattr(ip, "ipv4_mapped", None) is not None:
        raise ValueError("mapped address blocked")
    return requests.get(url).text


# Negative: an unrelated prefix check on the tainted host is not the
# incomplete-IPv6 shape.
@mcp.tool()
async def other_prefix(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g5-python
    if host.startswith("fe80:"):
        raise ValueError("link-local blocked")
    return requests.get(url).text


# Negative: recognized complete guard.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g5-python
    return requests.get(checked).text


# Negative: unrecognized helper guard; classify.py resolves the site as
# unrecognized-guard rather than G5.
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g5-python
    return requests.get(url).text


# Negative: textual mapped-prefix check outside any recognized handler
# source.
async def helper_v6(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g5-python
    if host.startswith("::ffff:"):
        raise ValueError("mapped address blocked")
    return requests.get(url).text
