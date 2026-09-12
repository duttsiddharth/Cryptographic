"""Filesystem scanner.

Two kinds of evidence are collected:

  Textual  — a rule fires on source or configuration. Cheap, broad, and needs a
             confidence score because a regex cannot tell a live call site from
             a comment.
  Parsed   — an actual X.509 certificate, private key, or SSH public key is
             read and its real algorithm and key size extracted. Expensive,
             narrow, and certain.

The parsed findings are the ones a CISO will act on first, because they name
a concrete artefact with a concrete expiry.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .rules import Rule, rules_for

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".idea", ".vscode", ".mypy_cache",
    ".pytest_cache", "vendor", ".terraform", "site-packages",
}

CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx"}
MAX_BYTES = 2_000_000


@dataclass
class Finding:
    path: str
    line: int
    algorithm: str
    rule_id: str
    description: str
    confidence: str
    evidence: str
    key_size: int | None = None
    detail: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.path, self.line, self.algorithm, self.rule_id)


def _iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None


def _curve_bits(curve_name: str) -> int | None:
    digits = "".join(c for c in curve_name if c.isdigit())
    return int(digits) if digits else None


def _describe_public_key(public_key) -> tuple[str, int | None, str]:
    """Return (catalogue algorithm name, key size in bits, human detail)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        name = public_key.curve.name
        return "ECDSA", _curve_bits(name), f"EC curve {name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed25519", 448, "Ed448"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, f"DSA-{public_key.key_size}"
    return type(public_key).__name__, None, type(public_key).__name__


def _scan_certificate(path: Path, raw: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        certificate = x509.load_pem_x509_certificate(raw)
    except Exception:
        try:
            certificate = x509.load_der_x509_certificate(raw)
        except Exception:
            return findings

    algorithm, bits, detail = _describe_public_key(certificate.public_key())
    if algorithm == "RSA" and bits:
        catalogue_name = "RSA"
    else:
        catalogue_name = algorithm

    try:
        subject = certificate.subject.rfc4514_string()
    except Exception:
        subject = "unknown subject"
    try:
        not_after = certificate.not_valid_after_utc.isoformat()
    except AttributeError:
        not_after = certificate.not_valid_after.isoformat()

    findings.append(Finding(
        path=str(path), line=0, algorithm=catalogue_name,
        rule_id="CERT-PARSE-001",
        description=f"X.509 certificate public key ({detail})",
        confidence="certain", evidence=subject[:180], key_size=bits,
        detail={"subject": subject, "expires": not_after,
                "serial": format(certificate.serial_number, "x")},
    ))

    signature_algorithm = (certificate.signature_algorithm_oid._name or "").lower()
    if "sha1" in signature_algorithm:
        hash_name = "SHA-1"
    elif "md5" in signature_algorithm:
        hash_name = "MD5"
    elif "sha256" in signature_algorithm:
        hash_name = "SHA-256"
    elif "sha384" in signature_algorithm:
        hash_name = "SHA-384"
    elif "sha512" in signature_algorithm:
        hash_name = "SHA-512"
    else:
        hash_name = None
    if hash_name:
        findings.append(Finding(
            path=str(path), line=0, algorithm=hash_name,
            rule_id="CERT-PARSE-002",
            description=f"Certificate signed with {signature_algorithm}",
            confidence="certain", evidence=subject[:180],
            detail={"signature_algorithm": signature_algorithm},
        ))
    return findings


def _scan_private_key(path: Path, raw: bytes) -> list[Finding]:
    try:
        private_key = serialization.load_pem_private_key(raw, password=None)
    except Exception:
        return []
    algorithm, bits, detail = _describe_public_key(private_key.public_key())
    return [Finding(
        path=str(path), line=0, algorithm=algorithm,
        rule_id="KEY-PARSE-001",
        description=f"Unencrypted private key on disk ({detail})",
        confidence="certain", evidence=detail, key_size=bits,
        detail={"encrypted": False},
    )]


def _scan_text(path: Path, text: str) -> list[Finding]:
    extension = path.suffix.lower()
    applicable = rules_for(extension)
    if not applicable:
        return []
    compiled: list[tuple[Rule, object]] = [(r, r.compiled()) for r in applicable]
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 1000:
            line = line[:1000]
        stripped = line.strip()
        if not stripped:
            continue
        commented = stripped.startswith(("#", "//", "*", "<!--", ";"))
        for rule, pattern in compiled:
            if pattern.search(line):
                confidence = "low" if commented else rule.confidence
                finding = Finding(
                    path=str(path), line=number, algorithm=rule.algorithm,
                    rule_id=rule.rule_id, description=rule.description,
                    confidence=confidence, evidence=stripped[:180],
                )
                if finding.key() in seen:
                    continue
                seen.add(finding.key())
                findings.append(finding)
    return findings


def scan(root: str | Path) -> list[Finding]:
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"No such path: {root}")
    if root.is_file():
        candidates = [root]
    else:
        candidates = list(_iter_files(root))

    findings: list[Finding] = []
    for path in candidates:
        extension = path.suffix.lower()
        if extension in CERT_EXT:
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            parsed = _scan_certificate(path, raw)
            if not parsed:
                parsed = _scan_private_key(path, raw)
            findings.extend(parsed)
            if parsed:
                continue
        text = _read_text(path)
        if text is None or "\x00" in text[:1024]:
            continue
        findings.extend(_scan_text(path, text))
    return findings
