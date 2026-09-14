# Synthetic recognized-complete target for CLI-level tests. The handler runs
# its URL through a complete-guard wrapper (resolve-all + range check +
# pinned connect) before the outbound request, so G0 stays quiet.
# Not imported or executed by pytest; scanned as data only.

import requests


def validate_public_url(url: str) -> str:
    # Placeholder for a resolve-all + range-check + pinned-connect guard.
    # The rules recognize the call shape by name; the body is out of scope
    # for intra-function taint.
    return url


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def fetch(url: str) -> str:
    checked = validate_public_url(url)
    return requests.get(checked).text
