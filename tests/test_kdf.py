import pytest
from cryptox.kdf.pbkdf import PBKDF2, bcrypt_derive


class TestPBKDF2:
    def test_derive(self):
        password = b"password123"
        kdf = PBKDF2(password)
        assert len(kdf.derived_key) == 32
        assert len(kdf.salt) == 16

    def test_verify_correct(self):
        password = b"password123"
        kdf = PBKDF2(password)
        assert PBKDF2.verify(password, kdf.salt, kdf.derived_key, kdf._iterations) is True

    def test_verify_incorrect(self):
        password = b"password123"
        kdf = PBKDF2(password)
        assert PBKDF2.verify(b"wrong", kdf.salt, kdf.derived_key, kdf._iterations) is False

    def test_hexderived(self):
        kdf = PBKDF2(b"password")
        assert isinstance(kdf.hexderived(), str)
        assert len(kdf.hexderived()) == 64

    def test_custom_salt(self):
        salt = b"fixed_salt_12345"
        kdf = PBKDF2(b"password", salt=salt)
        assert kdf.salt == salt

    def test_invalid_algorithm(self):
        with pytest.raises(ValueError):
            PBKDF2(b"password", algorithm="md5")

    def test_bcrypt_derive(self):
        key = bcrypt_derive(b"password", rounds=5)
        assert len(key) == 32
