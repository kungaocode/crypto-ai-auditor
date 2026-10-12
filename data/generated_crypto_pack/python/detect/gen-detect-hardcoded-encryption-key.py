from Crypto.Cipher import AES


def encrypt_customer_note(note: bytes) -> bytes:
    return AES.new(
        b"0123456789abcdef",
        AES.MODE_GCM,
        nonce=b"123456789012",
    ).encrypt(note)
