import pytest
from cryptox.signatures.ecdsa import ECDSA


class TestECDSA:
    def test_sign_verify(self):
        ecdsa = ECDSA(curve="SECP256R1")
        data = b"Test message for ECDSA"
        signature = ecdsa.sign(data)
        assert ecdsa.verify(data, signature) is True

    def test_verify_invalid(self):
        ecdsa = ECDSA(curve="SECP256R1")
        data = b"Original"
        wrong = b"Tampered"
        signature = ecdsa.sign(data)
        assert ecdsa.verify(wrong, signature) is False

    def test_curve_property(self):
        ecdsa = ECDSA(curve="SECP384R1")
        assert ecdsa.curve_name == "SECP384R1"

    def test_invalid_curve(self):
        with pytest.raises(ValueError):
            ECDSA(curve="INVALID")
