# ruleid: CRYPTO-011
user.password = password

# ruleid: CRYPTO-011
user.password = form_password

# ruleid: CRYPTO-011
account.passwd = pw

# ruleid: CRYPTO-011
user.set_password(plaintext_password)

# ok: stored value is a KDF digest, not the plaintext password
user.password = hash_password(password)

# ok
user.password_hash = hash_password(password)

# ok
user.password = pbkdf2_hmac("sha256", password.encode(), salt, 310000)
