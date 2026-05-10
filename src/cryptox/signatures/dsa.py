from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class DSA:
    SUPPORTED_KEY_SIZES = {1024, 2048, 3072}

    def __init__(self, key_size: int = 2048):
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Key size must be one of {self.SUPPORTED_KEY_SIZES}")
        self._key_size = key_size
        self._private_key = dsa.generate_private_key(
            key_size=key_size,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, hashes.SHA256())

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data, hashes.SHA256())
            return True
        except Exception:
            return False
