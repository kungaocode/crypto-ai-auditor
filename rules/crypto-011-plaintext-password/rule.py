# Static layer is deliberately all-alarm: any `.password = <anything>` fires,
# including assignments whose RHS is already a KDF digest. The triage layer
# rejects those benign assignments (the value is not plaintext).
import hashlib

# ruleid: CRYPTO-011
user.password = password

# ruleid: CRYPTO-011
user.password = form_password

# ruleid: CRYPTO-011
account.passwd = pw

# ruleid: CRYPTO-011
user.set_password(plaintext_password)

# ruleid: CRYPTO-011
# NOTE: RHS is a KDF digest -> triage must Reject, but the static rule still fires.
user.password = hash_password(password)

# ok
# NOTE: field name `password_hash` avoids the all-alarm pattern entirely.
user.password_hash = hash_password(password)

# ruleid: CRYPTO-011
# NOTE: RHS is a KDF digest -> triage must Reject, but the static rule still fires.
user.password = pbkdf2_hmac("sha256", password.encode(), salt, 310000)
