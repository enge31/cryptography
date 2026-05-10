from cryptox import AES, RSA, SHA256, HMAC, PBKDF2, ECDSA

def symmetric_example():
    print("=== Symmetric Encryption (AES-GCM) ===")
    key = AES.generate_key(32)
    iv = AES.generate_iv(16)
    cipher = AES(key, mode="GCM", iv=iv)
    plaintext = b"Hello, Cryptography!"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted.hex()[:32]}...")
    print(f"Decrypted:  {decrypted}")
    print()

def asymmetric_example():
    print("=== Asymmetric Encryption (RSA) ===")
    rsa = RSA(key_size=2048)
    plaintext = b"RSA works with small data"
    encrypted = rsa.encrypt(plaintext)
    decrypted = rsa.decrypt(encrypted)
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted.hex()[:32]}...")
    print(f"Decrypted:  {decrypted}")
    print()

    print("=== Digital Signature (RSA) ===")
    message = b"Sign this message"
    signature = rsa.sign(message)
    valid = rsa.verify(message, signature)
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:32]}...")
    print(f"Valid:      {valid}")
    print()

def hash_example():
    print("=== Hashing (SHA-256) ===")
    data = b"Hash this data"
    digest = SHA256.hash(data)
    print(f"Data:      {data}")
    print(f"SHA-256:   {digest.hex()}")
    print()

def hmac_example():
    print("=== HMAC ===")
    key = b"shared-secret"
    message = b"Authenticate this"
    h = HMAC(key, message)
    print(f"Message:   {message}")
    print(f"HMAC:      {h.hexdigest()}")
    print()

def kdf_example():
    print("=== Key Derivation (PBKDF2) ===")
    password = b"user-password"
    kdf = PBKDF2(password, iterations=100000)
    print(f"Salt:      {kdf.salt.hex()}")
    print(f"Derived:   {kdf.hexderived()}")
    print()

def ecdsa_example():
    print("=== ECDSA Signatures ===")
    ecdsa = ECDSA(curve="SECP256R1")
    message = b"ECDSA signed message"
    sig = ecdsa.sign(message)
    valid = ecdsa.verify(message, sig)
    print(f"Message:   {message}")
    print(f"Curve:     {ecdsa.curve_name}")
    print(f"Signature: {sig.hex()[:32]}...")
    print(f"Valid:     {valid}")
    print()

if __name__ == "__main__":
    symmetric_example()
    asymmetric_example()
    hash_example()
    hmac_example()
    kdf_example()
    ecdsa_example()
