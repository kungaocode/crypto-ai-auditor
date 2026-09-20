# ruleid: CRYPTO-008
iv = random.random()

# ruleid: CRYPTO-008
salt = random.getrandbits(128)

# ruleid: CRYPTO-008
token = random.choice(alphabet)

# ok
iv2 = secrets.token_bytes(16)

# ok
nonce = os.urandom(12)

# ok
junk = random.random()
