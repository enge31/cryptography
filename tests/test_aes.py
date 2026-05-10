import os
import pytest
from cryptox.symmetric.aes import AES


class TestAES:
    def test_encrypt_decrypt_cbc(self):
        key = AES.generate_key(32)
        iv = AES.generate_iv(16)
        plaintext = b"Hello, World! This is a test message."
        cipher = AES(key, mode="CBC", iv=iv)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_gcm(self):
        key = AES.generate_key(32)
        plaintext = b"GCM mode test data"
        cipher = AES(key, mode="GCM")
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_gcm_with_aad(self):
        key = AES.generate_key(32)
        plaintext = b"GCM with associated data"
        aad = b"authenticated but not encrypted"
        cipher = AES(key, mode="GCM")
        encrypted = cipher.encrypt(plaintext, associated_data=aad)
        decrypted = cipher.decrypt(encrypted, associated_data=aad)
        assert decrypted == plaintext

    def test_encrypt_decrypt_ctr(self):
        key = AES.generate_key(32)
        nonce = AES.generate_iv(16)
        plaintext = b"CTR mode test - stream cipher behavior"
        cipher = AES(key, mode="CTR", iv=nonce)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_ecb(self):
        key = AES.generate_key(32)
        plaintext = b"ECB mode test data!!"  # exactly 16 bytes
        cipher = AES(key, mode="ECB")
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            AES(b"tooshort")

    def test_invalid_mode(self):
        key = AES.generate_key(32)
        with pytest.raises(ValueError):
            AES(key, mode="INVALID")

    def test_generate_key_sizes(self):
        for size in [16, 24, 32]:
            key = AES.generate_key(size)
            assert len(key) == size

    def test_generate_iv(self):
        iv = AES.generate_iv(16)
        assert len(iv) == 16

    def test_key_size_property(self):
        key = AES.generate_key(32)
        cipher = AES(key)
        assert cipher.key_size == 256

    def test_mode_property(self):
        key = AES.generate_key(32)
        cipher = AES(key, mode="CTR")
        assert cipher.mode == "CTR"

    def test_encrypt_different_ivs(self):
        key = AES.generate_key(32)
        plaintext = b"Same plaintext, different IVs"
        c1 = AES(key, mode="CBC", iv=AES.generate_iv(16)).encrypt(plaintext)
        c2 = AES(key, mode="CBC", iv=AES.generate_iv(16)).encrypt(plaintext)
        assert c1 != c2

    def test_large_data(self):
        key = AES.generate_key(32)
        plaintext = os.urandom(100000)
        cipher = AES(key, mode="CBC", iv=AES.generate_iv(16))
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_cfb_mode(self):
        key = AES.generate_key(32)
        iv = AES.generate_iv(16)
        plaintext = b"CFB mode test"
        cipher = AES(key, mode="CFB", iv=iv)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_ofb_mode(self):
        key = AES.generate_key(32)
        iv = AES.generate_iv(16)
        plaintext = b"OFB mode test"
        cipher = AES(key, mode="OFB", iv=iv)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext
