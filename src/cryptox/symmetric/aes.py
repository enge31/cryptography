import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptox.utils.padding import PKCS7


class AES:
    SUPPORTED_KEYS = {16, 24, 32}
    SUPPORTED_MODES = {"CBC", "CTR", "GCM", "ECB", "CFB", "OFB"}

    def __init__(
        self,
        key: bytes,
        mode: str = "CBC",
        iv: Optional[bytes] = None,
        tag: Optional[bytes] = None,
    ):
        if len(key) not in self.SUPPORTED_KEYS:
            raise ValueError(
                f"Key must be {self.SUPPORTED_KEYS} bytes, got {len(key)}"
            )
        if mode.upper() not in self.SUPPORTED_MODES:
            raise ValueError(f"Mode must be one of {self.SUPPORTED_MODES}")

        self._key = key
        self._mode = mode.upper()
        self._backend = default_backend()
        self._iv = iv
        self._tag = tag

    @property
    def key_size(self) -> int:
        return len(self._key) * 8

    @property
    def mode(self) -> str:
        return self._mode

    @staticmethod
    def generate_key(size: int = 32) -> bytes:
        if size not in AES.SUPPORTED_KEYS:
            raise ValueError(f"Key size must be {AES.SUPPORTED_KEYS}")
        return os.urandom(size)

    @staticmethod
    def generate_iv(size: int = 16) -> bytes:
        return os.urandom(size)

    def _build_cipher(self, iv: bytes) -> Cipher:
        alg = algorithms.AES(self._key)

        mode_map = {
            "CBC": modes.CBC(iv),
            "CTR": modes.CTR(iv),
            "GCM": modes.GCM(iv),
            "ECB": modes.ECB(),
            "CFB": modes.CFB(iv),
            "OFB": modes.OFB(iv),
        }

        return Cipher(alg, mode_map[self._mode], backend=self._backend)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        iv = self._iv if self._iv is not None else os.urandom(16)

        if self._mode == "GCM":
            encryptor = self._build_cipher(iv).encryptor()
            if associated_data:
                encryptor.authenticate_additional_data(associated_data)
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return iv + ciphertext + encryptor.tag
        elif self._mode == "ECB":
            padded = PKCS7.pad(plaintext, 16)
            encryptor = self._build_cipher(iv).encryptor()
            return encryptor.update(padded) + encryptor.finalize()
        elif self._mode == "CTR":
            nonce = iv[:16]
            encryptor = self._build_cipher(nonce).encryptor()
            return nonce + encryptor.update(plaintext) + encryptor.finalize()
        else:
            padded = PKCS7.pad(plaintext, 16)
            encryptor = self._build_cipher(iv).encryptor()
            return iv + encryptor.update(padded) + encryptor.finalize()

    def decrypt(
        self,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None,
        tag: Optional[bytes] = None,
    ) -> bytes:
        if self._mode == "GCM":
            tag = tag or self._tag
            if tag is None:
                iv = ciphertext[:16]
                tag = ciphertext[-16:]
                ct = ciphertext[16:-16]
            else:
                iv = ciphertext[:16]
                ct = ciphertext[16:]
            decryptor = self._build_cipher(iv).decryptor()
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            pt = decryptor.update(ct)
            return pt + decryptor.finalize_with_tag(tag)
        elif self._mode == "CTR":
            nonce = ciphertext[:16]
            ct = ciphertext[16:]
            decryptor = self._build_cipher(nonce).decryptor()
            return decryptor.update(ct) + decryptor.finalize()
        elif self._mode == "ECB":
            decryptor = self._build_cipher(b"\x00" * 16).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            return PKCS7.unpad(padded, 16)
        else:
            iv = ciphertext[:16]
            ct = ciphertext[16:]
            decryptor = self._build_cipher(iv).decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            return PKCS7.unpad(padded, 16)
