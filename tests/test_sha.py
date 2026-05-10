import pytest
from cryptox.hash.sha import SHA256, SHA512


class TestSHA256:
    def test_hash_known(self):
        result = SHA256.hash(b"hello")
        assert result.hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_empty(self):
        result = SHA256.hash(b"")
        assert result.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_incremental(self):
        h = SHA256()
        h.update(b"hello")
        h.update(b" ")
        h.update(b"world")
        expected = SHA256.hash(b"hello world")
        assert h.digest() == expected

    def test_hexdigest(self):
        h = SHA256(b"test data")
        assert isinstance(h.hexdigest(), str)
        assert len(h.hexdigest()) == 64

    def test_digest_size(self):
        h = SHA256()
        assert h.digest_size == 32

    def test_copy(self):
        h1 = SHA256(b"hello")
        h2 = h1.copy()
        h1.update(b" world")
        h2.update(b" there")
        assert h1.digest() != h2.digest()


class TestSHA512:
    def test_hash_known(self):
        result = SHA512.hash(b"hello")
        known = (
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        )
        assert result.hex() == known

    def test_hash_empty(self):
        result = SHA512.hash(b"")
        known = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        assert result.hex() == known

    def test_digest_size(self):
        h = SHA512()
        assert h.digest_size == 64
