# Semgrep test fixture for rules/checklist/python-checklist.yaml.
# Annotations are the executable contract (semgrep test). Checklist rules
# enumerate manual-review candidates; every hit is a candidate, not a
# verdict.

import socket

import requests

mcp = None
server = None


# ruleid: mcp-ssrf-audit-checklist-g9-python
@mcp.tool()
def fetch(url: str, host: str) -> str:
    # ruleid: mcp-ssrf-audit-checklist-g7-python
    addr = socket.gethostbyname(host)
    # ruleid: mcp-ssrf-audit-checklist-g10-python
    headers = {"Authorization": "Bearer token"}
    # ruleid: mcp-ssrf-audit-checklist-g10-python
    return requests.get(url, headers=headers).text


# ruleid: mcp-ssrf-audit-checklist-g9-python
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    # ruleid: mcp-ssrf-audit-checklist-g7-python
    infos = socket.getaddrinfo(arguments["host"], 443)
    # ruleid: mcp-ssrf-audit-checklist-g10-python
    session.headers["X-API-Key"] = arguments["key"]
    return fetch(arguments["url"], arguments["host"])


def no_surface(x):
    # ok: mcp-ssrf-audit-checklist-g7-python
    # ok: mcp-ssrf-audit-checklist-g9-python
    # ok: mcp-ssrf-audit-checklist-g10-python
    return len(x)
