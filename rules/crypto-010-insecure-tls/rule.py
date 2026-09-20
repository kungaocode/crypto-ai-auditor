# ruleid: CRYPTO-010
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

# ruleid: CRYPTO-010
ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)

# ruleid: CRYPTO-010
ctx3 = ssl._create_unverified_context()

# ruleid: CRYPTO-010
requests.get(url, verify=False)

# ruleid: CRYPTO-010
ctx4.verify_mode = ssl.CERT_NONE

# ok
ctx5 = ssl.create_default_context()

# ok
requests.get(url, verify=True)
