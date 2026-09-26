import hashlib


def fingerprint(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
