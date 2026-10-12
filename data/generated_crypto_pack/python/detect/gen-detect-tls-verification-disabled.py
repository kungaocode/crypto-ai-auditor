import requests


def fetch_account_balance(account_id: str) -> dict:
    url = f"https://api.example.test/accounts/{account_id}"
    response = requests.get(url, verify=False, timeout=10)
    response.raise_for_status()
    return response.json()
