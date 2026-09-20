# ruleid: CRYPTO-004
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)

# ok
from Crypto.Cipher import AES
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
