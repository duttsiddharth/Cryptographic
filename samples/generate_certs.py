"""Generate the sample certificates and key for samples/legacy-bank.

These are deliberately not committed. A repository about cryptographic hygiene
should not ship a private key, even a throwaway one — secret scanners will flag
it, and the habit is the wrong one to model.

Run once before trying the worked example:

    python samples/generate_certs.py
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent / "legacy-bank" / "certs"


def certificate(path: Path, key, common_name: str) -> None:
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sample Cooperative Bank"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    built = (x509.CertificateBuilder()
             .subject_name(name).issuer_name(name)
             .public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now)
             .not_valid_after(now + datetime.timedelta(days=800))
             .sign(key, hashes.SHA256()))
    path.write_bytes(built.public_bytes(serialization.Encoding.PEM))
    print(f"wrote {path}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # Weak on classical grounds, before quantum is even considered.
    certificate(OUT / "legacy-branch.pem",
                rsa.generate_private_key(public_exponent=65537, key_size=1024),
                "legacy-branch.bank.local")
    # Sound today, broken by Shor's algorithm tomorrow.
    certificate(OUT / "core-api.pem",
                rsa.generate_private_key(public_exponent=65537, key_size=3072),
                "core-api.bank.local")
    certificate(OUT / "mobile-gw.pem",
                ec.generate_private_key(ec.SECP256R1()),
                "mobile-gw.bank.local")

    # An unencrypted private key left on disk, which is its own finding.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    target = OUT / "service.key"
    target.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
