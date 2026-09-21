import hmac
import secrets

# ruleid: CRYPTO-013
if user.password == input_password:
    login(user)

# ruleid: CRYPTO-013
if user.hash != provided_hash:
    reject()

# ruleid: CRYPTO-013
if session_token == guess:
    grant()

# ok: constant-time comparison
if hmac.compare_digest(user.password, input_password):
    login(user)

# ok
if secrets.compare_digest(stored, provided):
    print("tokens match")

# ok: non-credential equality is not in scope
if user.name == provided_name:
    print("same name")
