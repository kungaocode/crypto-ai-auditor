import hashlib

# ruleid: CRYPTO-002
h = hashlib.sha1(b"data")

# ruleid: CRYPTO-002
h2 = hashlib.new("sha1", b"data")

# ok
h3 = hashlib.sha256(b"data")

# ok
h4 = hashlib.new("sha256", b"data")
