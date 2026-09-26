"""Thin wrapper. Callers of protect do not name a hash or key type."""

from security.wrappers import seal_card_token


def protect(data: bytes) -> bytes:
    return seal_card_token(data)
