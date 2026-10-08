# Semgrep test fixture for mcp-ssrf-audit-g0-python.
# Annotations are the executable contract (semgrep test).
# G0 means "no recognized complete guard on the intra-function taint path".
# Weak and unrecognized guards do NOT suppress this rule; classify.py resolves
# the final class at the site per the layered resolution in
# docs/source-sink-matrix.md. Those lines are still positive annotations.

import ipaddress
import socket
from urllib.parse import urlparse

import aiohttp
import httpx
import requests

# Illustrative MCP decorator objects; the rule keys on the decorator method
# name (tool, call_tool, get_prompt), not the import.
mcp = None
server = None


# Positive: bare unguarded sink, decorator source. AE2 shape
# (client.get(url, follow_redirects=True) with nothing in between).
@mcp.tool()
async def fetch_tool(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g0-python
    resp = requests.get(url, allow_redirects=True)
    return resp.text


# Positive: urlparse-only path still fires. The incumbent registry rule is
# suppressed by any urlparse call; this is the regression case.
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    url = arguments["url"]
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("bad scheme")
    # ruleid: mcp-ssrf-audit-g0-python
    return httpx.get(url).text


# Positive: httpx client and aiohttp session sinks (incumbent sink gap).
@server.call_tool()
async def call_tool_clients(name: str, arguments: dict):
    url = arguments.get("url")
    async with httpx.AsyncClient() as client:
        # ruleid: mcp-ssrf-audit-g0-python
        await client.get(url)
    async with aiohttp.ClientSession() as session:
        # ruleid: mcp-ssrf-audit-g0-python
        await session.get(url)


# Positive: get_prompt source gap (incumbent misses this source shape).
@server.get_prompt()
async def get_prompt(name: str, arguments: dict):
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.get(arguments["url"]).text


# Positive: sync def under a bare decorator (no call parens).
@server.tool
def sync_tool(url: str) -> str:
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.post(url).text


# Positive: unrecognized helper guard. The helper is not in the
# complete-guard vocabulary, so taint flows and G0 still fires; classify.py
# reports this site as "guard detected, shape unrecognized, manual review".
@mcp.tool()
async def guarded_unknown(url: str) -> str:
    if not is_allowed(url):
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.get(url)


# Positive: helper-factored guard called as check-and-throw. Not in the
# complete-guard vocabulary, so G0 fires and classify.py marks the site
# unrecognized rather than silent.
@mcp.tool()
async def guarded_helper(url: str) -> str:
    validate_url(url)
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.get(url)


# Negative: recognized complete-guard call (resolve-all + range check +
# pinned connect, in the documented vocabulary) sanitizes the returned value.
@mcp.tool()
async def guarded_complete(url: str) -> str:
    checked = validate_public_url(url)
    # ok: mcp-ssrf-audit-g0-python
    return requests.get(checked)


# Negative: recognized complete-guard check-and-throw on a local derived
# from the tainted parameter (by-side-effect sanitizer).
@mcp.tool()
async def guarded_complete_throw(url: str) -> str:
    target = url
    assert_public_url(target)
    # ok: mcp-ssrf-audit-g0-python
    return requests.get(target)


# Known ceiling: a check-and-throw validator applied directly to the tainted
# parameter does not suppress the raw finding. Semgrep CE keeps the parameter
# binding tainted for the whole function body, so by-side-effect cannot clear
# it. The raw finding is expected; the complete-guard site probe resolves the
# site to recognized-complete at classify time.
@mcp.tool()
async def guarded_throw_on_param(url: str) -> str:
    assert_public_url(url)
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.get(url)


# Negative: hardcoded literal URL is not model-controlled.
@mcp.tool()
async def literal(url: str) -> str:
    # ok: mcp-ssrf-audit-g0-python
    return requests.get("https://example.com/feed").text


# Negative: sink outside any recognized handler source. The parameter is not
# a taint source here.
async def helper_fetch(url: str) -> str:
    # ok: mcp-ssrf-audit-g0-python
    return requests.get(url).text


# Dispatch-method source: class-based tool registry where the registered
# callback delegates to tool.execute(args) and the sink lives in the method.
class FetchTool:
    async def execute(self, args):
        # ruleid: mcp-ssrf-audit-g0-python
        return requests.get(args["url"]).text


def handle_call(args):
    # ruleid: mcp-ssrf-audit-g0-python
    return requests.get(args["url"]).text


# Negative: method on a class that is neither Tool-named nor takes a
# handler-arg-named parameter. The dispatch source requires an args-named
# param; the Tool-class source requires a Tool-named class.
class PayloadRunner:
    async def execute(self, payload):
        # ok: mcp-ssrf-audit-g0-python
        return requests.get(payload["url"]).text


# Framework tool-entry source: method on a Tool-named class delivering
# model args (Tool.forward shape).
class ReadWebpageTool:
    def forward(self, url: str) -> str:
        # ruleid: mcp-ssrf-audit-g0-python
        return requests.get(url).text


# Framework tool-entry source: **kwargs kwargs-dict arg (BaseTool._run shape),
# sink on a driver receiver.
class WebDriverScrapeTool:
    def _run(self, **kwargs):
        website_url = kwargs.get("website_url")
        # ruleid: mcp-ssrf-audit-g0-python
        return self.driver.get(website_url)


# Negative: same method name on a class that is not Tool-named.
class PlainWorker:
    def forward(self, url: str) -> str:
        # ok: mcp-ssrf-audit-g0-python
        return requests.get(url).text
