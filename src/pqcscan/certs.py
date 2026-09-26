from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqcscan.catalog import Q_CERT, Q_HASH_BROKEN
from pqcscan.discover import SourceFile
from pqcscan.models import Evidence, Finding

_PRIVATE_MARKERS = (
    b"BEGIN PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN ENCRYPTED PRIVATE KEY",
)
_WEAK_HASHES = {"sha1", "md5", "sha1-with-rsa", "md5-with-rsa"}


def _subject(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if names:
        return str(names[0].value)
    return cert.subject.rfc4514_string()


def _expires(cert: x509.Certificate) -> str:
    moment = getattr(cert, "not_valid_after_utc", None)
    if moment is None:
        moment = cert.not_valid_after
    return moment.isoformat()


def _public_key_facts(cert: x509.Certificate) -> tuple[str, str, str]:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        size = public_key.key_size
        concern = "urgent" if size < 2048 else "plan"
        return f"RSA-{size}", concern, f"RSA {size}-bit certificate key"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve.name
        return f"EC-{curve}", "plan", f"Elliptic-curve certificate key {curve}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", "plan", "Ed25519 certificate key"
    if isinstance(public_key, dsa.DSAPublicKey):
        return f"DSA-{public_key.key_size}", "urgent", f"DSA {public_key.key_size}-bit certificate key"
    return "unknown-public-key", "plan", "Unrecognized certificate public key"


def _load_certificates(data: bytes) -> list[x509.Certificate]:
    loaded: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        chunks = data.split(b"-----BEGIN CERTIFICATE-----")
        for chunk in chunks[1:]:
            pem = b"-----BEGIN CERTIFICATE-----" + chunk.split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
            loaded.append(x509.load_pem_x509_certificate(pem))
        return loaded
    if data[:1] == b"\x30":
        loaded.append(x509.load_der_x509_certificate(data))
    return loaded


def scan_certificate(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    if any(marker in source.data for marker in _PRIVATE_MARKERS):
        header = next(
            (line.strip() for line in source.text.splitlines() if "PRIVATE KEY" in line),
            "PRIVATE KEY header",
        )
        findings.append(
            Finding(
                rule_id="pem-private-key",
                name="Private key material",
                kind="secret_material",
                usage="keygen",
                underlying_usage="keygen",
                concern="urgent",
                confidence="confirmed",
                summary="A private key PEM header is present in this file. The key bytes are not copied into the report.",
                migration_hint="Remove private keys from the tree, rotate the key, and keep new keys in a managed store. This scanner does not read or export key material.",
                quantum_relevance="A private key in source control is an operational exposure. That is separate from whether the algorithm is a post-quantum migration candidate.",
                component=source.relative,
                evidence=[Evidence(source.relative, 1, header[:180])],
            )
        )
    if b"-----BEGIN CERTIFICATE-----" not in source.data and source.path.suffix.lower() != ".der":
        return findings
    try:
        certificates = _load_certificates(source.data)
    except ValueError as exc:
        findings.append(
            Finding(
                rule_id="pem-unparsed",
                name="Unparsed certificate",
                kind="certificate",
                usage="certificate",
                underlying_usage="certificate",
                concern="plan",
                confidence="uncertain",
                summary=f"Certificate bytes were found but could not be parsed ({exc.__class__.__name__}).",
                migration_hint="Open the file with a vetted certificate tool and record the key type and signature algorithm by hand.",
                quantum_relevance=Q_CERT,
                component=source.relative,
                evidence=[Evidence(source.relative, 1, "-----BEGIN CERTIFICATE-----")],
            )
        )
        return findings
    if not certificates:
        return findings
    for cert in certificates:
        key_name, concern, key_summary = _public_key_facts(cert)
        signature = cert.signature_hash_algorithm
        hash_name = signature.name if signature is not None else "none"
        if hash_name.lower() in _WEAK_HASHES:
            concern = "urgent"
        summary = (
            f"{key_summary}. Subject { _subject(cert) }. "
            f"Signature hash {hash_name}. Not after {_expires(cert)}."
        )
        findings.append(
            Finding(
                rule_id="x509-certificate",
                name=key_name,
                kind="certificate",
                usage="certificate",
                underlying_usage="certificate",
                concern=concern,
                confidence="confirmed",
                summary=summary,
                migration_hint=(
                    "Plan the certificate and its verifiers together. A post-quantum or composite "
                    "certificate is larger and is not a drop-in replacement. Parsing this file does not "
                    "make the deployment quantum-safe."
                ),
                quantum_relevance=Q_CERT,
                component=source.relative,
                evidence=[Evidence(source.relative, 1, summary)],
            )
        )
        if hash_name.lower() in _WEAK_HASHES:
            findings.append(
                Finding(
                    rule_id="x509-weak-hash",
                    name="SHA-1" if "sha1" in hash_name.lower() else "MD5",
                    kind="certificate",
                    usage="certificate",
                    underlying_usage="hash",
                    concern="urgent",
                    confidence="confirmed",
                    summary=f"Certificate signature hash is {hash_name}.",
                    migration_hint="Reissue the certificate with a current signature hash after verifiers are checked. This does not add post-quantum authentication by itself.",
                    quantum_relevance=Q_HASH_BROKEN,
                    component=source.relative,
                    evidence=[Evidence(source.relative, 1, f"signature hash {hash_name}")],
                )
            )
    return findings
