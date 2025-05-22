import hashlib

def hash_function(value: str) -> str:
    """Simulate a cryptographic hash function (SHA-3)."""
    return hashlib.sha3_256(value.encode()).hexdigest()
