import hashlib


def cache_key(public_config: bytes) -> str:
    return hashlib.md5(public_config).hexdigest()
