import hashlib


def routing_shard(tenant_id: str, shard_count: int) -> int:
    digest = hashlib.sha1(tenant_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % shard_count
