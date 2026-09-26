"""Design notes. Names here are discussion, not calls."""

# We might switch the archive format to RSA later if the bank asks.
# AES came up in the same review and no mode was chosen.
# ML-KEM was mentioned in a meeting and is not configured in this module.


def ready() -> bool:
    return True
