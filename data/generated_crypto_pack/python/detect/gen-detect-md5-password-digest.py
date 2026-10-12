import hashlib


def password_digest(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()
