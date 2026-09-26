from pathlib import Path

import pytest

from pqcscan.disclaimer import SANDBOX_DISCLAIMER
from pqcscan.sandbox.provider import (
    ClassicalProvider,
    OperationUnavailable,
    UnsupportedProfile,
    load_provider,
    run_demo,
)

ROOT = Path(__file__).resolve().parents[1]


def test_profiles_round_trip_and_are_not_interchangeable():
    message = b"crypto-agility-demo"
    p256 = ClassicalProvider("ecdsa-p256")
    p384 = ClassicalProvider("ecdsa-p384")
    signature = p256.sign(message)
    assert p256.verify(message, signature) is True
    assert p384.verify(message, signature) is False
    assert p384.verify(message, p384.sign(message)) is True
    aes = ClassicalProvider("aes-256-gcm")
    token = aes.protect(b"payload", b"aad")
    assert aes.open(token, b"aad") == b"payload"
    with pytest.raises(ValueError):
        aes.open(token, b"other")
    with pytest.raises(OperationUnavailable):
        aes.sign(message)
    rsa_provider = ClassicalProvider("rsa-pss-3072")
    rsa_signature = rsa_provider.sign(message)
    assert rsa_provider.verify(message, rsa_signature) is True
    assert p256.library == "cryptography"


def test_config_selects_the_provider():
    provider = load_provider(ROOT / "examples" / "sandbox" / "ecdsa-p256.json")
    assert provider.profile_id == "ecdsa-p256"
    assert provider.verify(b"config", provider.sign(b"config")) is True


def test_post_quantum_profiles_are_refused():
    with pytest.raises(UnsupportedProfile) as caught:
        ClassicalProvider("ml-kem-768")
    text = str(caught.value).lower()
    assert "custom cryptography" in text
    assert "refused" in text


def test_demo_states_the_limit():
    text = run_demo()
    assert SANDBOX_DISCLAIMER in text
    assert "verify=True" in text
    assert "round_trip=True" in text
    assert "quantum-safe" in text
    for line in text.splitlines():
        if "quantum-safe" in line.lower():
            assert "not" in line.lower()
