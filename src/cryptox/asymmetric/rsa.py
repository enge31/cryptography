import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from cryptox.utils.padding import PKCS7


@dataclass
class RSAKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    def to_pem(self, password: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pem, pub_pem

    @staticmethod
    def from_pem(
        priv_pem: Optional[bytes] = None,
        pub_pem: Optional[bytes] = None,
        password: Optional[bytes] = None,
    ):
        priv_key = None
        pub_key = None
        if priv_pem:
            priv_key = serialization.load_pem_private_key(priv_pem, password=password)
        if pub_pem:
            pub_key = serialization.load_pem_public_key(pub_pem)
        return RSAKeyPair(private_key=priv_key, public_key=pub_key)


class RSA:
    SUPPORTED_KEY_SIZES = {1024, 2048, 3072, 4096}

    def __init__(self, key_size: int = 2048):
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Key size must be one of {self.SUPPORTED_KEY_SIZES}")
        self._key_size = key_size
        self._keypair = self._generate()

    def _generate(self) -> RSAKeyPair:
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self._key_size,
            backend=default_backend(),
        )
        return RSAKeyPair(private_key=priv, public_key=priv.public_key())

    @property
    def keypair(self) -> RSAKeyPair:
        return self._keypair

    @property
    def public_key(self):
        return self._keypair.public_key

    @property
    def private_key(self):
        return self._keypair.private_key

    def encrypt(self, plaintext: bytes) -> bytes:
        max_len = (self._key_size // 8) - 42
        if len(plaintext) > max_len:
            raise ValueError(
                f"Plaintext too long for RSA key size {self._key_size}. "
                f"Max {max_len} bytes."
            )
        return self._keypair.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._keypair.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def sign(self, data: bytes) -> bytes:
        return self._keypair.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._keypair.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def export_pem(self, password: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        return self._keypair.to_pem(password)

    @staticmethod
    def load_pem(
        priv_pem: bytes,
        password: Optional[bytes] = None,
    ):
        priv = serialization.load_pem_private_key(priv_pem, password=password)
        key_size = priv.key_size
        rsa_obj = RSA.__new__(RSA)
        rsa_obj._key_size = key_size
        rsa_obj._keypair = RSAKeyPair(private_key=priv, public_key=priv.public_key())
        return rsa_obj

    @staticmethod
    def from_public_key_pem(pub_pem: bytes):
        pub = serialization.load_pem_public_key(pub_pem)
        rsa_obj = RSA.__new__(RSA)
        rsa_obj._key_size = pub.key_size
        rsa_obj._keypair = RSAKeyPair(private_key=None, public_key=pub)
        return rsa_obj


def generate_rsa_keypair(key_size: int = 2048) -> RSAKeyPair:
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return RSAKeyPair(private_key=priv, public_key=priv.public_key())
