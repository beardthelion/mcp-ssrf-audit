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


# Dispatch-method extent: class-based tool registry shape.
class FetchTool:
    # ruleid: mcp-ssrf-audit-probe-handler-source-python
    async def execute(self, args):
        # ruleid: mcp-ssrf-audit-probe-network-sink-python
        return requests.get(args["url"]).text


# ruleid: mcp-ssrf-audit-probe-handler-source-python
def handle_call(args):
    # ruleid: mcp-ssrf-audit-probe-network-sink-python
    return requests.get(args["url"]).text


class OtherTool:
    # ruleid: mcp-ssrf-audit-probe-handler-source-python
    async def execute(self, payload):
        # ruleid: mcp-ssrf-audit-probe-network-sink-python
        return requests.get(payload["url"]).text


# Framework tool-entry extent: Tool-named class with a forward method.
class ReadWebpageTool:
    # ruleid: mcp-ssrf-audit-probe-handler-source-python
    def forward(self, url: str) -> str:
        # ruleid: mcp-ssrf-audit-probe-network-sink-python
        return requests.get(url).text


# Framework tool-entry extent: _run with **kwargs (BaseTool._run shape) plus a
# driver.get sink on a driver receiver.
class WebDriverScrapeTool:
    # ruleid: mcp-ssrf-audit-probe-handler-source-python
    def _run(self, **kwargs):
        website_url = kwargs.get("website_url")
        # ruleid: mcp-ssrf-audit-probe-network-sink-python
        return self.driver.get(website_url)


# Negative: forward on a non-Tool class is not a handler extent.
class PlainWorker:
    # ok: mcp-ssrf-audit-probe-handler-source-python
    def forward(self, url: str) -> str:
        # ruleid: mcp-ssrf-audit-probe-network-sink-python
        return requests.get(url).text
