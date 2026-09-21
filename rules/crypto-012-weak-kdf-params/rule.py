import hashlib
from Crypto.Protocol.KDF import PBKDF2

# ruleid: CRYPTO-012
pbkdf2_hmac("sha256", password, salt, 1000)

# ruleid: CRYPTO-012
hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 10000)

# ruleid: CRYPTO-012
PBKDF2(password, salt, 16, count=1000)

# ruleid: CRYPTO-012
PBKDF2(password, salt, 16, 500)

# ok
hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 310000)

# ok
PBKDF2(password, salt, 16, 600000)
