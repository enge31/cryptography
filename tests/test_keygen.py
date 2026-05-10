from cryptox.keygen.keygen import generate_key, random_bytes, KeyPair


class TestKeygen:
    def test_generate_key(self):
        key = generate_key(32)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_random_bytes(self):
        data = random_bytes(16)
        assert len(data) == 16

    def test_keypair_dataclass(self):
        kp = KeyPair(
            private_key=b"priv",
            public_key=b"pub",
            algorithm="test",
            metadata={"version": 1},
        )
        assert kp.private_key == b"priv"
        assert kp.public_key == b"pub"
        assert kp.algorithm == "test"
        assert kp.metadata == {"version": 1}

    def test_keypair_to_dict(self):
        kp = KeyPair(b"priv", b"pub", "RSA")
        d = kp.to_dict()
        assert d["algorithm"] == "RSA"
        assert d["private_key"] == b"priv".hex()
        assert d["public_key"] == b"pub".hex()

    def test_generate_key_default(self):
        key = generate_key()
        assert len(key) == 32
