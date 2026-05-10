import pytest
from cryptox.asymmetric.rsa import RSA, generate_rsa_keypair


class TestRSA:
    def test_generate_keypair(self):
        rsa = RSA(key_size=2048)
        assert rsa.keypair is not None
        assert rsa.public_key is not None
        assert rsa.private_key is not None

    def test_encrypt_decrypt(self):
        rsa = RSA(key_size=2048)
        plaintext = b"Hello, RSA!"
        encrypted = rsa.encrypt(plaintext)
        decrypted = rsa.decrypt(encrypted)
        assert decrypted == plaintext

    def test_sign_verify(self):
        rsa = RSA(key_size=2048)
        data = b"Important message"
        signature = rsa.sign(data)
        assert rsa.verify(data, signature) is True

    def test_verify_invalid_signature(self):
        rsa = RSA(key_size=2048)
        data = b"Original message"
        wrong_data = b"Tampered message"
        signature = rsa.sign(data)
        assert rsa.verify(wrong_data, signature) is False

    def test_export_import_pem(self):
        rsa = RSA(key_size=2048)
        data = b"Roundtrip test"
        priv_pem, pub_pem = rsa.export_pem()
        rsa2 = RSA.load_pem(priv_pem)
        encrypted = rsa2.encrypt(data)
        decrypted = rsa.decrypt(encrypted)
        assert decrypted == data

    def test_export_import_with_password(self):
        rsa = RSA(key_size=2048)
        password = b"securepassword"
        priv_pem, pub_pem = rsa.export_pem(password=password)
        rsa2 = RSA.load_pem(priv_pem, password=password)
        assert rsa2.public_key is not None

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            RSA(key_size=512)

    def test_plaintext_too_long(self):
        rsa = RSA(key_size=1024)
        with pytest.raises(ValueError):
            rsa.encrypt(b"x" * 200)

    def test_generate_rsa_keypair_function(self):
        kp = generate_rsa_keypair(2048)
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_from_public_key_pem(self):
        rsa = RSA(key_size=2048)
        _, pub_pem = rsa.export_pem()
        rsa2 = RSA.from_public_key_pem(pub_pem)
        plaintext = b"Test public encryption"
        encrypted = rsa.encrypt(plaintext)
        # Can't decrypt with only public key, but we can sign/verify
        assert rsa2.public_key is not None

    def test_keypair_to_from_pem(self):
        kp = generate_rsa_keypair(2048)
        priv_pem, pub_pem = kp.to_pem()
        kp2 = generate_rsa_keypair(2048)
        kp_loaded = type(kp).from_pem(priv_pem, pub_pem)
        assert kp_loaded.private_key is not None
        assert kp_loaded.public_key is not None
