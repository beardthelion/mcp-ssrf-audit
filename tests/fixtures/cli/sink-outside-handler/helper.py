# Synthetic fixture: a network sink inside a function that is not a
# recognized MCP handler, next to a real handler with no sink. The sink
# must land on the coverage "outside recognized handlers" line rather
# than reading as an empty or a guarded scan (R12, KTD7).
# Not imported or executed by pytest; scanned as data only (R15).

import requests


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


def fetch_helper(url: str) -> str:
    return requests.get(url).text


@server.tool()
def describe(name: str) -> str:
    return f"describes {name}"
