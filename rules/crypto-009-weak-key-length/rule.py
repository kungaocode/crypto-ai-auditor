# ruleid: CRYPTO-009
key = RSA.generate(1024)

# ruleid: CRYPTO-009
priv = ec.generate_private_key(ec.SECP192R1())

# ok
key2 = RSA.generate(2048)

# ok
priv2 = ec.generate_private_key(ec.SECP384R1())
