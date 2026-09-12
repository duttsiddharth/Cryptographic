"""What each algorithm is worth once a cryptographically relevant quantum
computer exists.

Three things break differently:

  Asymmetric (RSA, ECC, DH, DSA)  — Shor's algorithm breaks these outright.
                                    Key size does not help. These must be
                                    replaced, not strengthened.
  Symmetric (AES, ChaCha20)       — Grover's algorithm halves the effective
                                    key length. AES-128 falls to 64 bits of
                                    security; AES-256 remains sound.
  Hashes (SHA-2, SHA-3)           — Grover applies to preimage resistance.
                                    SHA-256 is acceptable; longer is better.

Anything already broken classically (MD5, SHA-1, DES, RC4) is a finding
regardless of quantum, and usually the easier conversation to have first.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Risk(str, Enum):
    BROKEN_BY_QUANTUM = "broken_by_quantum"
    WEAKENED_BY_QUANTUM = "weakened_by_quantum"
    QUANTUM_SAFE = "quantum_safe"
    CLASSICALLY_BROKEN = "classically_broken"
    UNKNOWN = "unknown"


RISK_WEIGHT = {
    Risk.CLASSICALLY_BROKEN: 100,
    Risk.BROKEN_BY_QUANTUM: 80,
    Risk.WEAKENED_BY_QUANTUM: 35,
    Risk.UNKNOWN: 20,
    Risk.QUANTUM_SAFE: 0,
}

RISK_LABEL = {
    Risk.CLASSICALLY_BROKEN: "Broken today",
    Risk.BROKEN_BY_QUANTUM: "Broken by quantum",
    Risk.WEAKENED_BY_QUANTUM: "Weakened by quantum",
    Risk.QUANTUM_SAFE: "Quantum safe",
    Risk.UNKNOWN: "Needs review",
}


@dataclass(frozen=True)
class Algorithm:
    name: str
    family: str
    risk: Risk
    rationale: str
    replacement: str | None = None
    nist_standard: str | None = None


def _a(name, family, risk, rationale, replacement=None, standard=None):
    return Algorithm(name, family, risk, rationale, replacement, standard)


CATALOGUE: dict[str, Algorithm] = {
    a.name: a
    for a in [
        # -- asymmetric: replaced outright -------------------------------
        _a("RSA", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Shor's algorithm factors the modulus. Increasing key size does not help.",
           "ML-KEM for key establishment, ML-DSA for signatures", "FIPS 203 / 204"),
        _a("ECDSA", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Shor's algorithm solves the discrete log on elliptic curves.",
           "ML-DSA, or SLH-DSA where a conservative hash-based scheme is preferred",
           "FIPS 204 / 205"),
        _a("ECDH", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Shor's algorithm recovers the shared secret from public values.",
           "ML-KEM, deployed in hybrid with X25519 during transition", "FIPS 203"),
        _a("Ed25519", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "An Edwards-curve signature scheme, and so equally exposed to Shor.",
           "ML-DSA, or a hybrid Ed25519 + ML-DSA signature", "FIPS 204"),
        _a("X25519", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Curve25519 key agreement. Exposed to Shor like any discrete-log scheme.",
           "Hybrid X25519 + ML-KEM key exchange", "FIPS 203"),
        _a("DSA", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Finite-field discrete log, broken by Shor. Already deprecated by NIST.",
           "ML-DSA", "FIPS 204"),
        _a("DH", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Finite-field Diffie-Hellman, broken by Shor.",
           "ML-KEM in hybrid mode", "FIPS 203"),
        _a("ElGamal", "asymmetric", Risk.BROKEN_BY_QUANTUM,
           "Discrete-log based encryption, broken by Shor.", "ML-KEM", "FIPS 203"),

        # -- symmetric: strengthened, not replaced -----------------------
        _a("AES-128", "symmetric", Risk.WEAKENED_BY_QUANTUM,
           "Grover's algorithm halves the effective key length to roughly 64 bits.",
           "AES-256"),
        _a("AES-192", "symmetric", Risk.WEAKENED_BY_QUANTUM,
           "Grover leaves roughly 96 bits of effective security. Acceptable but not durable.",
           "AES-256"),
        _a("AES-256", "symmetric", Risk.QUANTUM_SAFE,
           "Grover leaves roughly 128 bits of effective security, which remains sound."),
        _a("ChaCha20", "symmetric", Risk.QUANTUM_SAFE,
           "A 256-bit stream cipher. Grover leaves roughly 128 bits."),
        _a("3DES", "symmetric", Risk.CLASSICALLY_BROKEN,
           "Sweet32 birthday attacks on the 64-bit block. Disallowed by NIST since 2023.",
           "AES-256"),
        _a("DES", "symmetric", Risk.CLASSICALLY_BROKEN,
           "A 56-bit key, brute-forced in hours on commodity hardware.", "AES-256"),
        _a("RC4", "symmetric", Risk.CLASSICALLY_BROKEN,
           "Biased keystream. Prohibited in TLS since RFC 7465.", "AES-256-GCM"),
        _a("Blowfish", "symmetric", Risk.CLASSICALLY_BROKEN,
           "A 64-bit block cipher, exposed to the same birthday bound as 3DES.",
           "AES-256"),

        # -- hashes -------------------------------------------------------
        _a("MD5", "hash", Risk.CLASSICALLY_BROKEN,
           "Practical collisions since 2004. Unfit for any security purpose.",
           "SHA-256 or SHA-3"),
        _a("SHA-1", "hash", Risk.CLASSICALLY_BROKEN,
           "Chosen-prefix collisions demonstrated in 2020. Withdrawn by NIST in 2030 plans.",
           "SHA-256 or SHA-3"),
        _a("SHA-256", "hash", Risk.WEAKENED_BY_QUANTUM,
           "Grover reduces preimage resistance to roughly 128 bits. Acceptable, "
           "but SHA-384 is the safer choice for long-lived signatures.",
           "SHA-384 for data with a long confidentiality horizon"),
        _a("SHA-384", "hash", Risk.QUANTUM_SAFE, "Ample margin against Grover."),
        _a("SHA-512", "hash", Risk.QUANTUM_SAFE, "Ample margin against Grover."),
        _a("SHA3-256", "hash", Risk.WEAKENED_BY_QUANTUM,
           "As with SHA-256, Grover leaves roughly 128 bits of preimage resistance.",
           "SHA3-384"),
        _a("SHA3-512", "hash", Risk.QUANTUM_SAFE, "Ample margin against Grover."),

        # -- password hashing --------------------------------------------
        _a("MD5-crypt", "kdf", Risk.CLASSICALLY_BROKEN,
           "Fast and unsalted in common configurations. Trivially cracked.",
           "Argon2id"),
        _a("PBKDF2", "kdf", Risk.QUANTUM_SAFE,
           "Not a quantum concern, but GPU-parallelisable. Iteration count matters.",
           "Argon2id where the platform allows"),
        _a("bcrypt", "kdf", Risk.QUANTUM_SAFE, "Not a quantum concern."),
        _a("scrypt", "kdf", Risk.QUANTUM_SAFE, "Memory-hard. Not a quantum concern."),
        _a("Argon2", "kdf", Risk.QUANTUM_SAFE, "Memory-hard. Current best practice."),

        # -- post-quantum --------------------------------------------------
        _a("ML-KEM", "pqc", Risk.QUANTUM_SAFE,
           "Module-lattice key encapsulation, standardised as FIPS 203.",
           None, "FIPS 203"),
        _a("ML-DSA", "pqc", Risk.QUANTUM_SAFE,
           "Module-lattice digital signatures, standardised as FIPS 204.",
           None, "FIPS 204"),
        _a("SLH-DSA", "pqc", Risk.QUANTUM_SAFE,
           "Stateless hash-based signatures, standardised as FIPS 205. Conservative "
           "choice where lattice assumptions are unwelcome.", None, "FIPS 205"),
        _a("Kyber", "pqc", Risk.QUANTUM_SAFE,
           "The pre-standard name for ML-KEM. Confirm the implementation tracks "
           "final FIPS 203 parameters, not a round-three draft.", None, "FIPS 203"),
        _a("Dilithium", "pqc", Risk.QUANTUM_SAFE,
           "The pre-standard name for ML-DSA. Confirm it tracks final FIPS 204.",
           None, "FIPS 204"),
        _a("Falcon", "pqc", Risk.QUANTUM_SAFE,
           "Selected by NIST as FN-DSA; the standard was still in draft as of 2026.",
           None, "FN-DSA (draft)"),

        # -- MAC ------------------------------------------------------------
        _a("HMAC", "mac", Risk.QUANTUM_SAFE,
           "Security rests on the key length, not on a hard mathematical problem."),
    ]
}


def lookup(name: str) -> Algorithm | None:
    return CATALOGUE.get(name)


def unknown(name: str) -> Algorithm:
    return Algorithm(
        name=name, family="unknown", risk=Risk.UNKNOWN,
        rationale="Not in the catalogue. Review manually and classify.",
    )
