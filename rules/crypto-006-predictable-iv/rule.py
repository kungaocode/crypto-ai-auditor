# ruleid: CRYPTO-006
cipher = AES.new(key, AES.MODE_CBC, iv=b"")

# ruleid: CRYPTO-006
c = Cipher(algorithms.AES(key), modes.CBC(b""))

# ruleid: CRYPTO-006
c2 = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))

# ok
c3 = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)))

# ok
c4 = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))
