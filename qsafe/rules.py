"""Detection rules.

Each rule maps a textual signature to an algorithm in the catalogue. Rules are
deliberately conservative: a rule that fires on every mention of the word "key"
produces an inventory nobody reads. Where a match is ambiguous, the rule carries
a lower confidence and the report says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    algorithm: str
    pattern: str
    description: str
    confidence: str = "high"  # high | medium | low
    extensions: tuple[str, ...] = ()

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern)


CODE_EXT = (".py", ".java", ".js", ".ts", ".go", ".rb", ".cs", ".c", ".cpp", ".php", ".kt", ".scala", ".rs")
CONF_EXT = (".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml", ".properties", ".xml", ".tf")

RULES: list[Rule] = [
    # -- Python -----------------------------------------------------------
    Rule("PY-RSA-001", "RSA", r"\brsa\.generate_private_key\s*\(",
         "RSA key generation via the cryptography library", "high", CODE_EXT),
    Rule("PY-RSA-002", "RSA", r"\bRSA\.generate\s*\(",
         "RSA key generation via PyCryptodome", "high", CODE_EXT),
    Rule("PY-EC-001", "ECDSA", r"\bec\.generate_private_key\s*\(",
         "Elliptic-curve key generation via the cryptography library", "high", CODE_EXT),
    Rule("PY-EC-002", "ECDSA", r"\bec\.ECDSA\s*\(",
         "ECDSA signature construction", "high", CODE_EXT),
    Rule("PY-ED-001", "Ed25519", r"\bEd25519PrivateKey\b|\bEd25519PublicKey\b",
         "Ed25519 signing key", "high", CODE_EXT),
    Rule("PY-X25-001", "X25519", r"\bX25519PrivateKey\b",
         "X25519 key agreement", "high", CODE_EXT),
    Rule("PY-DH-001", "DH", r"\bdh\.generate_parameters\s*\(",
         "Finite-field Diffie-Hellman parameters", "high", CODE_EXT),
    Rule("PY-AES-001", "AES-256", r"algorithms\.AES\s*\(\s*\w*key\w*\s*\)",
         "AES via the cryptography library; key length needs confirming", "low", CODE_EXT),
    Rule("PY-3DES-001", "3DES", r"algorithms\.TripleDES\s*\(|\bDES3\b",
         "Triple DES", "high", CODE_EXT),
    Rule("PY-MD5-001", "MD5", r"hashlib\.md5\s*\(|\bMD5\.new\s*\(",
         "MD5 hashing", "high", CODE_EXT),
    Rule("PY-SHA1-001", "SHA-1", r"hashlib\.sha1\s*\(|hashes\.SHA1\s*\(",
         "SHA-1 hashing", "high", CODE_EXT),
    Rule("PY-SHA256-001", "SHA-256", r"hashlib\.sha256\s*\(|hashes\.SHA256\s*\(",
         "SHA-256 hashing", "high", CODE_EXT),
    Rule("PY-PBKDF2-001", "PBKDF2", r"\bPBKDF2HMAC\s*\(|pbkdf2_hmac\s*\(",
         "PBKDF2 password derivation", "high", CODE_EXT),

    # -- Java -------------------------------------------------------------
    Rule("JV-RSA-001", "RSA", r"getInstance\s*\(\s*\"RSA",
         "RSA via the JCA", "high", CODE_EXT),
    Rule("JV-EC-001", "ECDSA", r"getInstance\s*\(\s*\"(EC|SHA\d+withECDSA)",
         "Elliptic-curve key or ECDSA signature via the JCA", "high", CODE_EXT),
    Rule("JV-DSA-001", "DSA", r"getInstance\s*\(\s*\"(DSA|SHA\d*withDSA)",
         "DSA via the JCA", "high", CODE_EXT),
    Rule("JV-DH-001", "DH", r"getInstance\s*\(\s*\"(DH|DiffieHellman)\"",
         "Diffie-Hellman via the JCA", "high", CODE_EXT),
    Rule("JV-MD5-001", "MD5", r"getInstance\s*\(\s*\"MD5\"",
         "MD5 via the JCA", "high", CODE_EXT),
    Rule("JV-SHA1-001", "SHA-1", r"getInstance\s*\(\s*\"SHA-?1\"",
         "SHA-1 via the JCA", "high", CODE_EXT),
    Rule("JV-3DES-001", "3DES", r"getInstance\s*\(\s*\"(DESede|TripleDES)",
         "Triple DES via the JCA", "high", CODE_EXT),
    Rule("JV-DES-001", "DES", r"getInstance\s*\(\s*\"DES[\"/]",
         "Single DES via the JCA", "high", CODE_EXT),

    # -- JavaScript / Node -------------------------------------------------
    Rule("JS-RSA-001", "RSA", r"generateKeyPair(Sync)?\s*\(\s*[\"']rsa[\"']",
         "RSA key generation in Node", "high", CODE_EXT),
    Rule("JS-EC-001", "ECDSA", r"generateKeyPair(Sync)?\s*\(\s*[\"']ec[\"']",
         "Elliptic-curve key generation in Node", "high", CODE_EXT),
    Rule("JS-ED-001", "Ed25519", r"generateKeyPair(Sync)?\s*\(\s*[\"']ed25519[\"']",
         "Ed25519 key generation in Node", "high", CODE_EXT),
    Rule("JS-MD5-001", "MD5", r"createHash\s*\(\s*[\"']md5[\"']",
         "MD5 hashing in Node", "high", CODE_EXT),
    Rule("JS-SHA1-001", "SHA-1", r"createHash\s*\(\s*[\"']sha1[\"']",
         "SHA-1 hashing in Node", "high", CODE_EXT),
    Rule("JS-JWT-001", "RSA", r"algorithm\s*:\s*[\"']RS(256|384|512)[\"']",
         "RSA-signed JSON Web Tokens", "high", CODE_EXT),
    Rule("JS-JWT-002", "ECDSA", r"algorithm\s*:\s*[\"']ES(256|384|512)[\"']",
         "ECDSA-signed JSON Web Tokens", "high", CODE_EXT),

    # -- Go -----------------------------------------------------------------
    Rule("GO-RSA-001", "RSA", r"rsa\.GenerateKey\s*\(",
         "RSA key generation in Go", "high", CODE_EXT),
    Rule("GO-EC-001", "ECDSA", r"ecdsa\.GenerateKey\s*\(",
         "ECDSA key generation in Go", "high", CODE_EXT),
    Rule("GO-ED-001", "Ed25519", r"ed25519\.GenerateKey\s*\(",
         "Ed25519 key generation in Go", "high", CODE_EXT),
    Rule("GO-MD5-001", "MD5", r"md5\.(New|Sum)\s*\(", "MD5 in Go", "high", CODE_EXT),
    Rule("GO-SHA1-001", "SHA-1", r"sha1\.(New|Sum)\s*\(", "SHA-1 in Go", "high", CODE_EXT),

    # -- TLS configuration ---------------------------------------------------
    Rule("TLS-RSA-001", "RSA", r"\bTLS_RSA_WITH_\w+",
         "TLS cipher suite using RSA key transport", "high", CONF_EXT),
    Rule("TLS-ECDHE-001", "ECDH", r"\bECDHE[-_]",
         "TLS cipher suite using ephemeral elliptic-curve key exchange", "high", CONF_EXT),
    Rule("TLS-DHE-001", "DH", r"\bDHE[-_]RSA|\bTLS_DHE_",
         "TLS cipher suite using ephemeral finite-field Diffie-Hellman", "high", CONF_EXT),
    Rule("TLS-3DES-001", "3DES", r"\b(3DES|DES-CBC3)\b",
         "Triple DES offered in a TLS cipher list", "high", CONF_EXT),
    Rule("TLS-RC4-001", "RC4", r"\bRC4\b", "RC4 offered in a TLS cipher list", "high", CONF_EXT),
    Rule("TLS-AES128-001", "AES-128", r"\bAES[-_]?128\b",
         "AES-128 cipher suite", "high", CONF_EXT),
    Rule("TLS-AES256-001", "AES-256", r"\bAES[-_]?256\b",
         "AES-256 cipher suite", "high", CONF_EXT),
    Rule("CFG-SHA1-001", "SHA-1", r"\bsha1WithRSA|\bSHA1\b",
         "SHA-1 referenced in configuration", "medium", CONF_EXT),

    # -- SSH -------------------------------------------------------------------
    Rule("SSH-RSA-001", "RSA", r"\bssh-rsa\b", "SSH RSA host or user key", "high",
         CONF_EXT + (".pub", "")),
    Rule("SSH-ED-001", "Ed25519", r"\bssh-ed25519\b", "SSH Ed25519 key", "high",
         CONF_EXT + (".pub", "")),
    Rule("SSH-ECDSA-001", "ECDSA", r"\becdsa-sha2-nistp\d+\b", "SSH ECDSA key", "high",
         CONF_EXT + (".pub", "")),

    # -- post-quantum already present --------------------------------------------
    Rule("PQ-MLKEM-001", "ML-KEM", r"\bML[-_]?KEM\b", "ML-KEM in use", "high",
         CODE_EXT + CONF_EXT),
    Rule("PQ-MLDSA-001", "ML-DSA", r"\bML[-_]?DSA\b", "ML-DSA in use", "high",
         CODE_EXT + CONF_EXT),
    Rule("PQ-SLHDSA-001", "SLH-DSA", r"\bSLH[-_]?DSA\b", "SLH-DSA in use", "high",
         CODE_EXT + CONF_EXT),
    Rule("PQ-KYBER-001", "Kyber", r"\bkyber\d*\b", "Kyber, the pre-standard ML-KEM",
         "high", CODE_EXT + CONF_EXT),
    Rule("PQ-DILI-001", "Dilithium", r"\bdilithium\d*\b",
         "Dilithium, the pre-standard ML-DSA", "high", CODE_EXT + CONF_EXT),
]


def rules_for(extension: str) -> list[Rule]:
    out = []
    for rule in RULES:
        if not rule.extensions or extension in rule.extensions:
            out.append(rule)
    return out
