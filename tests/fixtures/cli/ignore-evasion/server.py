# Evasion fixture: this directory ships a .semgrepignore that tries to
# exclude every Python file. The runner passes
# --x-ignore-semgrepignore-files, so the file is still scanned and the
# ignore file is listed in the coverage summary.
# Scanned as data only; never executed.

import requests


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
