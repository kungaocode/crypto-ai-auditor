import ssl

import requests


def build_api_client() -> requests.Session:
    context = ssl.create_default_context()
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter()
    session.mount("https://", adapter)
    session.verify = context
    return session
