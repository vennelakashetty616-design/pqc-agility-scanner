from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcscan.disclaimer import SANDBOX_DISCLAIMER

# Lowercase identifiers only. Canonical NIST spellings are omitted so this
# denylist is not mistaken for an implementation of those algorithms.
_REFUSED_MARKERS = (
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
    "fn-dsa",
    "kyber",
    "dilithium",
    "sphincs",
    "falcon",
)


class OperationUnavailable(Exception):
    """The selected profile does not offer this operation."""


class UnsupportedProfile(Exception):
    """The profile is unknown or intentionally refused."""


class CryptoProvider(Protocol):
    """Caller-facing agility interface. Implementations must come from vetted libraries."""

    profile_id: str
    library: str

    def capabilities(self) -> frozenset[str]: ...

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...

    def protect(self, plaintext: bytes, associated_data: bytes = b"") -> bytes: ...

    def open(self, token: bytes, associated_data: bytes = b"") -> bytes: ...


@dataclass(frozen=True)
class ProfileSpec:
    profile_id: str
    operations: frozenset[str]
    description: str


PROFILES: dict[str, ProfileSpec] = {
    "aes-256-gcm": ProfileSpec(
        "aes-256-gcm",
        frozenset({"protect", "open"}),
        "AES-256-GCM through cryptography.hazmat AESGCM. Ephemeral key, in memory only.",
    ),
    "ecdsa-p256": ProfileSpec(
        "ecdsa-p256",
        frozenset({"sign", "verify"}),
        "ECDSA on P-256 with SHA-256 through the cryptography package. Ephemeral key, in memory only.",
    ),
    "ecdsa-p384": ProfileSpec(
        "ecdsa-p384",
        frozenset({"sign", "verify"}),
        "ECDSA on P-384 with SHA-384 through the cryptography package. Ephemeral key, in memory only.",
    ),
    "rsa-pss-3072": ProfileSpec(
        "rsa-pss-3072",
        frozenset({"sign", "verify"}),
        "RSA-PSS with a 3072-bit key and SHA-256 through the cryptography package. Ephemeral key, in memory only.",
    ),
}


class _AesGcm:
    def __init__(self) -> None:
        self._box = AESGCM(AESGCM.generate_key(bit_length=256))

    def protect(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._box.encrypt(nonce, plaintext, associated_data)

    def open(self, token: bytes, associated_data: bytes) -> bytes:
        if len(token) < 13:
            raise ValueError("Token is too short for an AES-GCM nonce and ciphertext.")
        try:
            return self._box.decrypt(token[:12], token[12:], associated_data)
        except InvalidTag as exc:
            raise ValueError("AES-GCM authentication failed.") from exc


class _Ecdsa:
    def __init__(self, curve: ec.EllipticCurve, digest: hashes.HashAlgorithm) -> None:
        self._key = ec.generate_private_key(curve)
        self._digest = digest

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message, ec.ECDSA(self._digest))

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._key.public_key().verify(signature, message, ec.ECDSA(self._digest))
        except InvalidSignature:
            return False
        return True


class _RsaPss:
    def __init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._key.public_key().verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        return True


def _build(profile_id: str) -> _AesGcm | _Ecdsa | _RsaPss:
    if profile_id == "aes-256-gcm":
        return _AesGcm()
    if profile_id == "ecdsa-p256":
        return _Ecdsa(ec.SECP256R1(), hashes.SHA256())
    if profile_id == "ecdsa-p384":
        return _Ecdsa(ec.SECP384R1(), hashes.SHA384())
    if profile_id == "rsa-pss-3072":
        return _RsaPss()
    raise UnsupportedProfile(profile_id)


class ClassicalProvider:
    """Classical profiles backed only by the cryptography package."""

    library = "cryptography"

    def __init__(self, profile_id: str) -> None:
        key = profile_id.strip().lower()
        if key not in PROFILES:
            if any(marker in key for marker in _REFUSED_MARKERS):
                raise UnsupportedProfile(
                    f"Profile {profile_id!r} is refused. This sandbox does not implement post-quantum algorithms "
                    "and will not substitute custom cryptography. Use a vetted library such as OpenSSL 3.5+ or liboqs, "
                    "then call that library from behind CryptoProvider."
                )
            known = ", ".join(sorted(PROFILES))
            raise UnsupportedProfile(f"Unknown profile {profile_id!r}. Classical profiles: {known}.")
        self.profile_id = key
        self.profile = PROFILES[key]
        self._impl = _build(key)

    def capabilities(self) -> frozenset[str]:
        return self.profile.operations

    def _require(self, operation: str) -> None:
        if operation not in self.profile.operations:
            raise OperationUnavailable(
                f"Profile {self.profile_id} does not provide {operation}. Capabilities: {', '.join(sorted(self.profile.operations))}."
            )

    def sign(self, message: bytes) -> bytes:
        self._require("sign")
        return self._impl.sign(message)  # type: ignore[union-attr]

    def verify(self, message: bytes, signature: bytes) -> bool:
        self._require("verify")
        return self._impl.verify(message, signature)  # type: ignore[union-attr]

    def protect(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        self._require("protect")
        return self._impl.protect(plaintext, associated_data)  # type: ignore[union-attr]

    def open(self, token: bytes, associated_data: bytes = b"") -> bytes:
        self._require("open")
        return self._impl.open(token, associated_data)  # type: ignore[union-attr]


def load_provider(path: Path) -> ClassicalProvider:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UnsupportedProfile(f"Sandbox config is not JSON: {path}") from exc
    profile = data.get("profile") if isinstance(data, dict) else None
    if not isinstance(profile, str):
        raise UnsupportedProfile("Sandbox config must contain a string profile field.")
    return ClassicalProvider(profile)


def list_profiles() -> list[ProfileSpec]:
    return [PROFILES[key] for key in sorted(PROFILES)]


def run_demo() -> str:
    message = b"crypto-agility-demo"
    p256 = ClassicalProvider("ecdsa-p256")
    p384 = ClassicalProvider("ecdsa-p384")
    signature = p256.sign(message)
    aes = ClassicalProvider("aes-256-gcm")
    token = aes.protect(b"payload", b"aad")
    rsa_provider = ClassicalProvider("rsa-pss-3072")
    rsa_signature = rsa_provider.sign(message)
    lines = [
        SANDBOX_DISCLAIMER,
        f"Profile {p256.profile_id} library={p256.library} capabilities={','.join(sorted(p256.capabilities()))} verify={p256.verify(message, signature)}",
        f"Profile {p384.profile_id} library={p384.library} verify={p384.verify(message, p384.sign(message))}",
        f"Cross-check p256 signature under p384 session verify={p384.verify(message, signature)}",
        "The caller used the same sign and verify methods. Only the profile name changed.",
        "Each session generates an ephemeral key in memory. Keys are not written to disk.",
        f"Profile aes-256-gcm round_trip={aes.open(token, b'aad') == b'payload'}",
        f"Profile rsa-pss-3072 verify={rsa_provider.verify(message, rsa_signature)}",
    ]
    return "\n".join(lines)
