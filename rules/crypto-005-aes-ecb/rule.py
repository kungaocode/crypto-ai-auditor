# ruleid: CRYPTO-005
cipher = AES.new(key, AES.MODE_ECB)

# ok
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)

# ruleid: CRYPTO-005
cipher3 = Cipher(algorithms.AES(key), modes.ECB())

# ok
cipher4 = Cipher(algorithms.AES(key), modes.GCM(nonce))
