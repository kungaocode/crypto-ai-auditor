import base64
import hashlib
import hmac


class TokenSigner:
    def __init__(self, secret: bytes):
        self._secret = secret

    def sign(self, user_id: str) -> str:
        payload = base64.urlsafe_b64encode(user_id.encode("utf-8"))
        mac = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return payload.decode("ascii") + "." + base64.urlsafe_b64encode(mac).decode("ascii")

    def verify(self, token: str, user_id: str) -> bool:
        payload = base64.urlsafe_b64encode(user_id.encode("utf-8"))
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
        try:
            _, encoded_mac = token.rsplit(".", 1)
            provided = base64.urlsafe_b64decode(encoded_mac)
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(provided, expected)
