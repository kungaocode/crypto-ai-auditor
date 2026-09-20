import hashlib

# ruleid: CRYPTO-001
h = hashlib.md5(b"data")

# ruleid: CRYPTO-001
h2 = hashlib.new("md5", b"data")

# ok
h3 = hashlib.sha256(b"data")

# ok
h4 = hashlib.new("sha256", b"data")
