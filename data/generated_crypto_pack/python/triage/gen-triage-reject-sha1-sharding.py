import hashlib


def shard_for_tenant(tenant_id: str, shard_count: int) -> int:
    digest = hashlib.sha1(tenant_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % shard_count
