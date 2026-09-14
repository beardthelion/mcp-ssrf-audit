# Synthetic G7/G10 checklist-candidate target for CLI-level tests (AE3
# analogue). The handler resolves the hostname and then fetches the URL,
# so the resolve call is a G7 candidate (verify connect-time pinning) and
# the auth-header dict is a G10 candidate. Neither emits a deterministic
# finding by itself; the taint path resolves deterministically per
# whichever class rules are present (requests.get follows redirects by
# default, so the site labels G6 once that rule ships).
# Not imported or executed by pytest; scanned as data only (R15).

import requests
import socket


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def fetch(url: str, host: str) -> str:
    addr = socket.gethostbyname(host)
    return requests.get(url, headers={"Authorization": "Bearer token"}).text
