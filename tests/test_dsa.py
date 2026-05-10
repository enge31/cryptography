import pytest
from cryptox.signatures.dsa import DSA


class TestDSA:
    def test_sign_verify(self):
        dsa = DSA(key_size=1024)
        data = b"Test message for DSA"
        signature = dsa.sign(data)
        assert dsa.verify(data, signature) is True

    def test_verify_invalid(self):
        dsa = DSA(key_size=1024)
        data = b"Original"
        wrong = b"Tampered"
        signature = dsa.sign(data)
        assert dsa.verify(wrong, signature) is False

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            DSA(key_size=512)
