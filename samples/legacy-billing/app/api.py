"""HTTP-facing helper that never names an algorithm."""

from billing import charge


def collect(card_number: bytes) -> bytes:
    return charge(card_number)
