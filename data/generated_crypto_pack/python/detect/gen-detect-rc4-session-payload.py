from Crypto.Cipher import ARC4


def encrypt_session_payload(key: bytes, payload: bytes) -> bytes:
    return ARC4.new(key).encrypt(payload)
