from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_profile(key: bytes, profile: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return encryptor.update(profile) + encryptor.finalize()
