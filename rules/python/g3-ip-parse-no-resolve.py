# Semgrep test fixture for mcp-ssrf-audit-g3-python.
# G3: the guard parses the host as an IP literal (ipaddress.ip_address,
# inet_aton, inet_pton) and range-checks it, but never resolves the hostname
# through DNS in the same function. Any resolvable name for a private
# address (127.0.0.1.nip.io, a controlled A record) passes, and
# non-canonical IP spellings the parser rejects fall through as "not an IP".

import ipaddress
import socket
from urllib.parse import urlparse

import requests

mcp = None
server = None


# Positive: praisonai spider_tools shape - ipaddress.ip_address on the
# hostname, ValueError means "not an IP literal, allow it".
@mcp.tool()
async def ip_parse_no_dns(url: str) -> str:
    host = urlparse(url).hostname
    try:
        # ruleid: mcp-ssrf-audit-g3-python
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback):
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: IPv4Address constructor and a bare from-import form.
@server.call_tool()
async def ip_ctor(name: str, arguments: dict):
    url = arguments["url"]
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g3-python
    if ipaddress.IPv4Address(host).is_private:
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g3-python
    if ip_address(host).is_loopback:
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: inet_aton/inet_pton are literal parses, not DNS resolution.
@mcp.tool()
async def inet_aton_parse(url: str) -> str:
    host = urlparse(url).hostname
    try:
        # ruleid: mcp-ssrf-audit-g3-python
        packed = socket.inet_aton(host)
        if packed == b"\x7f\x00\x00\x01":
            raise ValueError("blocked")
    except OSError:
        pass
    return requests.get(url).text


# Negative: the same parse plus DNS resolution in the same function is the
# resolve-then-check shape (complete guard or G7 territory, not G3).
@mcp.tool()
async def resolve_then_parse(url: str) -> str:
    host = urlparse(url).hostname
    for info in socket.getaddrinfo(host, None):
        # ok: mcp-ssrf-audit-g3-python
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback:
            raise ValueError("blocked")
    return requests.get(url).text


# Negative: gethostbyname resolution feeds the parse.
@mcp.tool()
async def gethostbyname_then_parse(url: str) -> str:
    host = urlparse(url).hostname
    addr = socket.gethostbyname(host)
    # ok: mcp-ssrf-audit-g3-python
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        raise ValueError("blocked")
    return requests.get(url).text


# Negative: recognized complete guard; the tainted value never reaches a
# literal IP parse.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g3-python
    return requests.get(checked).text


# Negative: unrecognized helper guard; classify.py reports the site as
# unrecognized-guard rather than G3.
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g3-python
    return requests.get(url).text


# Negative: literal parse outside any recognized handler source.
async def helper_parse(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g3-python
    ip = ipaddress.ip_address(host)
    if ip.is_loopback:
        raise ValueError("blocked")
    return requests.get(url).text
