import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def issue_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def customer_reference(pan: str) -> str:
    return hashlib.md5(pan.encode()).hexdigest()

def settlement_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def channel_key():
    return ec.generate_private_key(ec.SECP256R1())
