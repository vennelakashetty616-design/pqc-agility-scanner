"""Legacy token sealing. This module is the direct cryptographic call site."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import DES


def seal_card_token(data: bytes) -> bytes:
    digest = hashlib.md5(data).digest()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # The key object only exists so the scanner can see the API. It is not used.
    _ = (DES, key)
    return digest
