from Crypto.Cipher import DES


def test_des_known_vector():
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    assert cipher.encrypt(b"plaintex") == bytes.fromhex(
        "5b21b1b349b3c5f0"
    )
