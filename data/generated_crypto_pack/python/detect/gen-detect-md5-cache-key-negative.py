import hashlib


def config_cache_key(public_config: bytes) -> str:
    return "config:" + hashlib.md5(public_config).hexdigest()
