import hashlib


def set_account_password(password: str) -> str:
    verifier = hashlib.md5(password.encode("utf-8")).hexdigest()
    return verifier
