import hashlib


def store(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, salt, 1000)
