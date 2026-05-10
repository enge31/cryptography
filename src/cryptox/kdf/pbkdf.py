import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class PBKDF2:
    SUPPORTED_HASHES = {"sha256", "sha384", "sha512"}

    def __init__(
        self,
        password: bytes,
        salt: Optional[bytes] = None,
        iterations: int = 600000,
        dklen: int = 32,
        algorithm: str = "sha256",
    ):
        if algorithm not in self.SUPPORTED_HASHES:
            raise ValueError(f"Algorithm must be one of {self.SUPPORTED_HASHES}")

        self._salt = salt if salt is not None else os.urandom(16)
        self._iterations = iterations
        self._dklen = dklen
        self._algorithm = algorithm

        hash_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }

        self._kdf = PBKDF2HMAC(
            algorithm=hash_map[algorithm],
            length=dklen,
            salt=self._salt,
            iterations=iterations,
            backend=default_backend(),
        )
        self._derived_key = self._kdf.derive(password)

    @property
    def salt(self) -> bytes:
        return self._salt

    @property
    def derived_key(self) -> bytes:
        return self._derived_key

    def hexderived(self) -> str:
        return self._derived_key.hex()

    @staticmethod
    def verify(password: bytes, salt: bytes, derived: bytes, iterations: int = 600000, algorithm: str = "sha256") -> bool:
        hash_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }
        kdf = PBKDF2HMAC(
            algorithm=hash_map[algorithm],
            length=len(derived),
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        try:
            kdf.verify(password, derived)
            return True
        except Exception:
            return False

    @staticmethod
    def hash(
        password: bytes,
        salt: Optional[bytes] = None,
        iterations: int = 600000,
        algorithm: str = "sha256",
    ):
        pbkdf2 = PBKDF2(password, salt, iterations, algorithm=algorithm)
        return pbkdf2.derived_key, pbkdf2.salt


def bcrypt_derive(password: bytes, salt: Optional[bytes] = None, rounds: int = 12) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations=2**rounds,
        dklen=32,
    )
    return derived
