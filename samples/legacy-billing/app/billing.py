"""Billing entry point. Crypto details sit behind security.facade."""

from security.facade import protect


def charge(card_number: bytes) -> bytes:
    return protect(card_number)
