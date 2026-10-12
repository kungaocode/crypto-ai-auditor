from Crypto.Cipher import AES


def encrypt_account_record(key: bytes, record: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(record.ljust(16 * ((len(record) + 15) // 16), b"\x00"))
