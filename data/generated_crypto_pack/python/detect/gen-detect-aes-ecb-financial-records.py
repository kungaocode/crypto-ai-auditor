from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_financial_record(key: bytes, record: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(record, AES.block_size))
