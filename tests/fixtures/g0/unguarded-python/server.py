# Synthetic G0 target for CLI-level tests. A minimal MCP-style server whose
# tool handler passes the model-supplied URL straight to requests.get.
# Not imported or executed by pytest; scanned as data only (R15).

import requests


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def fetch(url: str) -> str:
    return requests.get(url, allow_redirects=True).text
