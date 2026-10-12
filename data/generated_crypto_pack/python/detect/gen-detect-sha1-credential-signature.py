import hashlib


def sign_login_assertion(secret: bytes, assertion: bytes) -> str:
    return hashlib.sha1(secret + assertion).hexdigest()
