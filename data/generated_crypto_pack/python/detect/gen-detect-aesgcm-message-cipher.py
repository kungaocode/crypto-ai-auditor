import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessageCipher:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 128, 192, or 256 bits")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, plaintext, aad)

    def decrypt(self, payload: bytes, aad: bytes = b"") -> bytes:
        nonce, ciphertext = payload[:12], payload[12:]
        return self._cipher.decrypt(nonce, ciphertext, aad)
