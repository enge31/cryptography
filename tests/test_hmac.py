import pytest
from cryptox.hmac import HMAC


class TestHMAC:
    def test_hmac_sha256(self):
        key = b"secret"
        data = b"message"
        h = HMAC(key, data)
        assert len(h.digest()) == 32

    def test_verify_correct(self):
        key = b"secret"
        data = b"message"
        sig = HMAC(key, data).digest()
        assert HMAC.verify(key, data, sig) is True

    def test_verify_incorrect(self):
        key = b"secret"
        data = b"message"
        sig = HMAC(key, data).digest()
        assert HMAC.verify(key, b"wrong", sig) is False

    def test_incremental(self):
        key = b"key"
        h = HMAC(key)
        h.update(b"hello ")
        h.update(b"world")
        expected = HMAC(key, b"hello world")
        assert h.digest() == expected.digest()

    def test_hexdigest(self):
        key = b"key"
        data = b"data"
        h = HMAC(key, data)
        assert isinstance(h.hexdigest(), str)

    def test_copy(self):
        key = b"key"
        h1 = HMAC(key, b"hello")
        h2 = h1.copy()
        h1.update(b" world")
        h2.update(b" there")
        assert h1.digest() != h2.digest()

    def test_invalid_algorithm(self):
        with pytest.raises(ValueError):
            HMAC(b"key", algorithm="invalid")
