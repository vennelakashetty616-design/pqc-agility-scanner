"""Write a public sample certificate. The private key stays in memory and is not saved."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "samples" / "legacy-billing" / "certs" / "billing.crt"


def main() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "billing.example.invalid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Legacy Billing Sample"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
