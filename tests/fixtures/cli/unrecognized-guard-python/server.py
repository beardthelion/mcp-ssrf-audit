# Synthetic unrecognized-guard target for CLI-level tests (AE5). The
# handler routes the model-supplied URL through a helper whose name reads
# as validation but matches no known weak class and is not in the
# complete-guard vocabulary, so the site must resolve to
# "guard detected, shape unrecognized, manual review" rather than silence
# or G0.
# Not imported or executed by pytest; scanned as data only (R15).

import requests


def check_url_allowed(url: str) -> str:
    # Placeholder for a guard whose shape no rule recognizes.
    return url


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def fetch(url: str) -> str:
    checked = check_url_allowed(url)
    # allow_redirects=False keeps this site off the redirect class rules so
    # it exercises the unrecognized-guard resolution specifically.
    return requests.get(checked, allow_redirects=False).text
