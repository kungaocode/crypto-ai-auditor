# ruleid: CRYPTO-007
cipher = AES.new(b"0123456789abcdef", AES.MODE_CBC, iv=os.urandom(16))

# ruleid: CRYPTO-007
c = Cipher(algorithms.AES(b"0123456789abcdef"), modes.CBC(iv))

# ruleid: CRYPTO-007
f = Fernet("0123456789abcdef0123456789abcdef0123456789ab=")

# ok
cipher2 = AES.new(load_key(), AES.MODE_GCM, nonce=os.urandom(12))

# ok
c2 = Cipher(algorithms.AES(load_key()), modes.GCM(nonce))
