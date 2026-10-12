from Crypto.Cipher import ARC4


def benchmark_arc4(data: bytes) -> int:
    for _ in range(100):
        ARC4.new(b"bench-key").encrypt(data)
    return len(data)
