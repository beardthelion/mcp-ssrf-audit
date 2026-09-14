# Semgrep test fixture for mcp-ssrf-audit-g6-python.
# G6: the entry URL is validated but the client follows redirects, so a
# 30x target is fetched without re-validation. The deterministic shape is a
# tainted URL reaching a redirect-following sink inside a function that also
# calls a guard-ish named helper. requests/Session/aiohttp/urlopen and
# browser.goto follow redirects by default; httpx needs an explicit
# follow_redirects=True.
#
# The raw G0 rule still fires on the same sinks; classify.py relabels.

import socket
import urllib.request
from urllib.parse import urlparse

import httpx
import requests

mcp = None
server = None


def _is_safe_url(url: str) -> bool:
    """A validation helper by name; body irrelevant to the fixture."""
    return True


# Positive: pre-request validation, then a requests call that follows
# redirects by default (praisonai spider_tools scrape_page shape:
# self._validate_url(url) then session.get(url)).
@mcp.tool()
async def prereq_then_requests(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g6-python
    return requests.get(url).text


# Positive: validation then an explicit follow_redirects=True httpx call.
@server.call_tool()
async def prereq_then_httpx_kwarg(name: str, arguments: dict):
    url = arguments["url"]
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g6-python
    return httpx.get(url, follow_redirects=True).text


# Positive: validation then a client constructed with follow_redirects=True
# (praisonai web_crawl _crawl_with_httpx shape).
@mcp.tool()
async def prereq_then_client_ctor(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        # ruleid: mcp-ssrf-audit-g6-python
        resp = client.get(url)
    return resp.text


# Positive: validation then a requests.Session get; sessions follow
# redirects by default.
@mcp.tool()
async def prereq_then_session(url: str) -> str:
    if not self._validate_url(url):
        raise ValueError("blocked")
    session = requests.Session()
    # ruleid: mcp-ssrf-audit-g6-python
    return session.get(url).text


# Positive: validation then urlopen; the default urllib opener installs
# HTTPRedirectHandler, so redirects are followed unvalidated (the persistent
# G6 in the patched web_crawl_tools fallback).
@mcp.tool()
async def prereq_then_urlopen(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g6-python
    return urllib.request.urlopen(url, timeout=30).read()


# Positive: validation then an explicit allow_redirects=True session call.
@mcp.tool()
async def prereq_then_allow_redirects(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    session = requests.Session()
    # ruleid: mcp-ssrf-audit-g6-python
    return session.get(url, allow_redirects=True).text


# Ceiling documented in docs/source-sink-matrix.md: a check-and-throw
# complete-vocabulary guard on the raw parameter does not clear the taint
# (parameter stickiness), and requests.get still follows redirect hops the
# entry guard never saw. The finding is intended: entry validation with a
# default-redirect client is exactly the G6 gap.
@mcp.tool()
async def throw_guard_then_requests(url: str) -> str:
    assert_public_url(url)
    # ruleid: mcp-ssrf-audit-g6-python
    return requests.get(url).text


# Positive, multi-class site (a site carries a set of classes): this function carries a literal
# string blocklist (fires mcp-ssrf-audit-g2-python when the pack runs) and a
# validated-then-redirect-following fetch (G6 here).
@mcp.tool()
async def blocklist_plus_redirect(url: str) -> str:
    host = urlparse(url).hostname
    if host in ("localhost", "127.0.0.1"):
        raise ValueError("blocked")
    if not recheck_url(url):
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g6-python
    return requests.get(url).text


# Negative: redirect-policy wrapper - the client is constructed with
# follow_redirects=False and each hop is re-validated before connect
# (patched web_crawl_tools shape).
@mcp.tool()
async def per_hop_wrapper(url: str) -> str:
    current = url
    with httpx.Client(follow_redirects=False, timeout=30.0) as client:
        for _ in range(6):
            if not _is_safe_url(current):
                raise ValueError("redirect target failed validation")
            # ok: mcp-ssrf-audit-g6-python
            resp = client.get(current)
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            current = resp.headers.get("Location")
    return resp.text


# Negative: validation present but the request disables redirects.
@mcp.tool()
async def redirects_disabled(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g6-python
    return requests.get(url, allow_redirects=False).text


# Negative: validation present, httpx default client (httpx does not follow
# redirects unless opted in).
@mcp.tool()
async def httpx_default(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g6-python
    return httpx.get(url).text


# Negative: recognized complete guard; the returned value is sanitized, so
# nothing tainted reaches the redirect-following sink.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g6-python
    return requests.get(checked).text


# Negative: no guard-ish call anywhere in the function. This site is G0, not
# G6; the gate keeps unguarded sinks on the G0 label.
@mcp.tool()
async def unguarded(url: str) -> str:
    # ok: mcp-ssrf-audit-g6-python
    return requests.get(url).text


# Negative: validated fetch outside any recognized handler source.
async def helper_fetch(url: str) -> str:
    if not _is_safe_url(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g6-python
    return requests.get(url).text
