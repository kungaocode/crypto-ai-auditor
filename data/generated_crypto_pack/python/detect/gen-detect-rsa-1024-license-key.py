from Crypto.PublicKey import RSA


def generate_license_signing_key():
    return RSA.generate(1024)
