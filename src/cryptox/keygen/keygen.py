import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class KeyPair:
    private_key: bytes
    public_key: bytes
    algorithm: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "metadata": self.metadata,
        }


def generate_key(length: int = 32, algorithm: Optional[str] = None) -> bytes:
    return os.urandom(length)


def random_bytes(length: int = 32) -> bytes:
    return os.urandom(length)
