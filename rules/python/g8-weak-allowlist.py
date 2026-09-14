# Semgrep test fixture for the G8 rule file:
#   mcp-ssrf-audit-g8-python               (taint: unanchored host checks)
#   mcp-ssrf-audit-g8-python-env-killswitch (search: env-var guard bypass)
#   mcp-ssrf-audit-g8-python-default-off    (search: allowlist defaults off)
#
# G8: the allowlist exists but is easy to bypass or off by default - prefix
# or substring checks on the URL/host, regexes without anchors, an
# environment kill-switch, or an allowlist that defaults to empty/None.

import os
import re
from urllib.parse import urlparse

import requests

mcp = None
server = None


# Positive: prefix allowlist on the raw URL. "https://api.example.com"
# startswith-matches "https://api.example.com.evil.example" - unanchored.
@mcp.tool()
async def prefix_allowlist(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g8-python
    if url.startswith("https://api.example.com"):
        return requests.get(url).text
    raise ValueError("not allowed")


# Positive: suffix allowlist on the host. endswith("example.com") matches
# "notexample.com" (***REMOVED*** _is_url_match domain-only shapes reduce to
# this class of textual check).
@server.call_tool()
async def suffix_allowlist(name: str, arguments: dict):
    url = arguments["url"]
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g8-python
    if host.endswith("example.com"):
        return requests.get(url).text
    raise ValueError("not allowed")


# Positive: substring check - "example.com" in url matches
# "https://evil.example/?q=example.com".
@mcp.tool()
async def substring_allowlist(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g8-python
    if "example.com" in url:
        return requests.get(url).text
    raise ValueError("not allowed")


# Positive: re.match without an end anchor - re.match("example\.com", host)
# matches the "example.com" prefix of "example.com.evil".
@mcp.tool()
async def regex_no_end_anchor(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g8-python
    if re.match("example\\.com", host):
        return requests.get(url).text
    raise ValueError("not allowed")


# Positive: re.search is unanchored at both ends by design.
@mcp.tool()
async def regex_search(url: str) -> str:
    host = urlparse(url).hostname
    # ruleid: mcp-ssrf-audit-g8-python
    if re.search("example", host):
        return requests.get(url).text
    raise ValueError("not allowed")


# Positive: env-var kill-switch gating the guard (praisonai
# ALLOW_LOCAL_CRAWL shape). This is a search-mode rule; it fires on the env
# read itself, not on taint.
@mcp.tool()
async def env_killswitch(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g8-python-env-killswitch
    if os.environ.get("ALLOW_LOCAL_CRAWL") == "true":
        return requests.get(url).text
    if not is_allowed(url):
        raise ValueError("blocked")
    return requests.get(url).text


# Positive: os.getenv and subscript forms, and a disable-flag name
# (MCP_FETCH_DISABLE_SSRF_GUARD shape).
@mcp.tool()
async def env_killswitch_variants(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g8-python-env-killswitch
    if os.getenv("MCP_FETCH_DISABLE_SSRF_GUARD"):
        return requests.get(url).text
    # ruleid: mcp-ssrf-audit-g8-python-env-killswitch
    if os.environ["ALLOW_PRIVATE_NETWORKS"] == "1":
        return requests.get(url).text
    raise ValueError("blocked")


# Positive: allowlist defaulting to empty/None (***REMOVED*** profile shape:
# allowed_domains defaults to None and _is_url_allowed returns True when it
# is unset).
# ruleid: mcp-ssrf-audit-g8-python-default-off
allowed_domains: list = None
# ruleid: mcp-ssrf-audit-g8-python-default-off
allowed_hosts = []
# ruleid: mcp-ssrf-audit-g8-python-default-off
block_ip_addresses: bool = Field(default=False, description="off by default")


class Config:
    # ruleid: mcp-ssrf-audit-g8-python-default-off
    allowed_domains: list = Field(default=None, description="empty allowlist")

    # ruleid: mcp-ssrf-audit-g8-python-default-off
    def fetch(self, url: str, permitted_domains=None):
        if not is_allowed(url):
            raise ValueError("blocked")
        return requests.get(url).text


# Negative: anchored regexes and exact membership are not the unanchored
# shape.
@mcp.tool()
async def anchored_checks(url: str) -> str:
    host = urlparse(url).hostname
    # ok: mcp-ssrf-audit-g8-python
    if re.match("example\\.com$", host):
        return requests.get(url).text
    # ok: mcp-ssrf-audit-g8-python
    if re.fullmatch("[a-z]+\\.example\\.com", host):
        return requests.get(url).text
    # ok: mcp-ssrf-audit-g8-python
    if host in ALLOWED_SET:
        return requests.get(url).text
    raise ValueError("not allowed")


# Negative: a non-security env read (API keys, feature flags) is not a guard
# bypass.
@mcp.tool()
async def env_benign(url: str) -> str:
    # ok: mcp-ssrf-audit-g8-python-env-killswitch
    api_key = os.getenv("EXAMPLE_API_KEY")
    # ok: mcp-ssrf-audit-g8-python-env-killswitch
    if os.environ.get("LOG_LEVEL") == "debug":
        print(api_key)
    return requests.get(url).text


# Negative: env read of a non-literal name (config indirection) is not a
# recognizable kill-switch.
@mcp.tool()
async def env_indirect(url: str) -> str:
    # ok: mcp-ssrf-audit-g8-python-env-killswitch
    flag = os.environ.get(os.environ["FLAG_NAME"])
    return requests.get(url).text


# Negative: populated or non-allowlist defaults.
# ok: mcp-ssrf-audit-g8-python-default-off
allowed_origins = ["https://example.com"]
# ok: mcp-ssrf-audit-g8-python-default-off
request_timeout: int = Field(default=30)
# ok: mcp-ssrf-audit-g8-python-default-off
page_limit: int = None


# Negative: recognized complete guard - no unanchored check on the path.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g8-python
    return requests.get(checked).text


# Negative: unrecognized helper guard; classify.py reports the site as
# unrecognized-guard rather than G8.
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ok: mcp-ssrf-audit-g8-python
    return requests.get(url).text


# Negative: unanchored check outside any recognized handler source.
async def helper_prefix(url: str) -> str:
    # ok: mcp-ssrf-audit-g8-python
    if url.startswith("https://api.example.com"):
        return requests.get(url).text
    raise ValueError("not allowed")
