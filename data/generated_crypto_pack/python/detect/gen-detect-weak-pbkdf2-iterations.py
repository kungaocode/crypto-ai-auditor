import hashlib


def derive_password_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1200, dklen=32)
