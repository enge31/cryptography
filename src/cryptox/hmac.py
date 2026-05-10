import hmac as _hmac
import hashlib
from typing import Optional


class HMAC:
    SUPPORTED_ALGORITHMS = {"sha1", "sha256", "sha384", "sha512", "md5"}

    def __init__(
        self,
        key: bytes,
        data: Optional[bytes] = None,
        algorithm: str = "sha256",
    ):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algorithm must be one of {self.SUPPORTED_ALGORITHMS}")
        self._algorithm = algorithm
        self._hmac = _hmac.new(key, digestmod=algorithm)
        if data:
            self._hmac.update(data)

    def update(self, data: bytes) -> None:
        self._hmac.update(data)

    def digest(self) -> bytes:
        return self._hmac.digest()

    def hexdigest(self) -> str:
        return self._hmac.hexdigest()

    def copy(self):
        new = HMAC.__new__(HMAC)
        new._algorithm = self._algorithm
        new._hmac = self._hmac.copy()
        return new

    @staticmethod
    def verify(key: bytes, data: bytes, signature: bytes, algorithm: str = "sha256") -> bool:
        expected = HMAC(key, data, algorithm).digest()
        return _hmac.compare_digest(expected, signature)

    @staticmethod
    def hash(message: bytes, key: bytes, algorithm: str = "sha256") -> str:
        return HMAC(key, message, algorithm).hexdigest()
