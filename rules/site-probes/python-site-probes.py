# Semgrep test fixture for rules/site-probes/python-site-probes.yaml.
# Annotations are the executable contract (semgrep test). These rules are
# enumerators: every match is a location mark, never a verdict.

import requests

mcp = None
server = None


# ruleid: mcp-ssrf-audit-probe-handler-source-python
@mcp.tool()
def fetch(url: str) -> str:
    # ruleid: mcp-ssrf-audit-probe-network-sink-python
    return requests.get(url).text


# ruleid: mcp-ssrf-audit-probe-handler-source-python
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    url = arguments["url"]
    # ruleid: mcp-ssrf-audit-probe-complete-guard-python
    checked = pinned_request(url)
    # ruleid: mcp-ssrf-audit-probe-network-sink-python
    return requests.get(checked).text


# ruleid: mcp-ssrf-audit-probe-handler-source-python
@server.get_prompt()
async def get_prompt(name: str, arguments: dict):
    url = arguments["url"]
    # ruleid: mcp-ssrf-audit-probe-intervening-validation-python
    check_allowlist(url)
    # ruleid: mcp-ssrf-audit-probe-intervening-validation-python
    if not ok:
        raise ValueError("blocked")
    # ruleid: mcp-ssrf-audit-probe-network-sink-python
    return client_session.get(url).text


def no_surface(url: str) -> str:
    # ok: mcp-ssrf-audit-probe-handler-source-python
    # ok: mcp-ssrf-audit-probe-network-sink-python
    return render(url)
