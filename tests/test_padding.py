import pytest
from cryptox.utils.padding import PKCS7, pad, unpad


class TestPKCS7:
    def test_pad_roundtrip(self):
        for length in range(0, 256):
            data = b"x" * length
            padded = PKCS7.pad(data, 16)
            unpadded = PKCS7.unpad(padded, 16)
            assert unpadded == data

    def test_pad_adds_correct_bytes(self):
        padded = PKCS7.pad(b"x" * 10, 16)
        assert len(padded) == 16
        assert padded[-6:] == b"\x06" * 6

    def test_pad_exact_block(self):
        padded = PKCS7.pad(b"x" * 16, 16)
        assert len(padded) == 32

    def test_unpad_invalid_padding(self):
        with pytest.raises(ValueError):
            PKCS7.unpad(b"\x00\x00\x00\x00", 4)

    def test_unpad_empty(self):
        with pytest.raises(ValueError):
            PKCS7.unpad(b"", 16)

    def test_is_padded(self):
        data = PKCS7.pad(b"hello", 16)
        assert PKCS7.is_padded(data) is True
        assert PKCS7.is_padded(b"not padded") is False

    def test_pad_unpad_functions(self):
        data = b"test data"
        assert unpad(pad(data, 16), 16) == data
