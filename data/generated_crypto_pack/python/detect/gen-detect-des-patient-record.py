from Crypto.Cipher import DES


def encrypt_patient_record(key: bytes, data: bytes) -> bytes:
    block = data.ljust(16 * ((len(data) + 15) // 16), b"\x00")
    return DES.new(key, DES.MODE_ECB).encrypt(block)
