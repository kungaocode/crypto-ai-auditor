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

# ruleid: CRYPTO-012
bcrypt.gensalt(rounds=4)

# ruleid: CRYPTO-012
hashlib.scrypt(b"pw", salt=b"salt", n=1024, r=8, p=1)

# ok
hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 310000)

# ok
PBKDF2(password, salt, 16, 600000)

# ok
bcrypt.gensalt(rounds=12)

# ok
hashlib.scrypt(b"pw", salt=b"salt", n=16384, r=8, p=1)
