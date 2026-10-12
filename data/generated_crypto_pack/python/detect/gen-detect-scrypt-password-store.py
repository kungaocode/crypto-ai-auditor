import hashlib
import hmac
import os


class PasswordStore:
    N = 2**15
    R = 8
    P = 1
    KEY_LEN = 32

    def hash_password(self, password: str) -> bytes:
        salt = os.urandom(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=self.N,
            r=self.R,
            p=self.P,
            dklen=self.KEY_LEN,
        )
        return salt + digest

    def verify_password(self, password: str, stored: bytes) -> bool:
        salt, expected = stored[:16], stored[16:]
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=self.N,
            r=self.R,
            p=self.P,
            dklen=self.KEY_LEN,
        )
        return hmac.compare_digest(actual, expected)
