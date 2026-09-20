# ruleid: CRYPTO-003
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# ruleid: CRYPTO-003
from Crypto.Cipher import DES3
cipher2 = DES3.new(key, DES3.MODE_ECB)

# ok
from Crypto.Cipher import AES
cipher3 = AES.new(key, AES.MODE_GCM, nonce=nonce)
