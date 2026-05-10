from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class ECDSA:
    SUPPORTED_CURVES = {
        "SECP256R1": ec.SECP256R1,
        "SECP384R1": ec.SECP384R1,
        "SECP521R1": ec.SECP521R1,
        "SECP256K1": ec.SECP256K1,
    }

    def __init__(self, curve: str = "SECP256R1"):
        if curve not in self.SUPPORTED_CURVES:
            raise ValueError(f"Curve must be one of {list(self.SUPPORTED_CURVES.keys())}")
        self._curve_name = curve
        self._curve = self.SUPPORTED_CURVES[curve]()
        self._private_key = ec.generate_private_key(
            self._curve,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    @property
    def curve_name(self) -> str:
        return self._curve_name

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
