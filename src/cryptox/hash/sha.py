import hashlib
from typing import Optional


class _SHA:
    def __init__(self, data: bytes = b"", algorithm: str = "sha256"):
        self._algorithm = algorithm
        self._hasher = hashlib.new(algorithm)
        if data:
            self._hasher.update(data)

    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    def digest(self) -> bytes:
        return self._hasher.digest()

    def hexdigest(self) -> str:
        return self._hasher.hexdigest()

    def copy(self):
        new = _SHA(algorithm=self._algorithm)
        new._hasher = self._hasher.copy()
        return new

    @property
    def block_size(self) -> int:
        return self._hasher.block_size

    @property
    def digest_size(self) -> int:
        return self._hasher.digest_size

    @staticmethod
    def hash(data: bytes) -> bytes:
        raise NotImplementedError

    @staticmethod
    def hmac(key: bytes, data: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", key, data, 1, dklen=None)


class SHA256(_SHA):
    def __init__(self, data: bytes = b""):
        super().__init__(data, algorithm="sha256")

    @staticmethod
    def hash(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def file(path: str, chunk_size: int = 65536) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()


class SHA512(_SHA):
    def __init__(self, data: bytes = b""):
        super().__init__(data, algorithm="sha512")

    @staticmethod
    def hash(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

    @staticmethod
    def file(path: str, chunk_size: int = 65536) -> str:
        h = hashlib.sha512()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
