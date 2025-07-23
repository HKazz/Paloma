import os
import base64
import hashlib
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Generate a random 256-bit AES key
def generate_aes_key() -> bytes:
    # Return a base64-encoded 32-byte key for Fernet
    return base64.urlsafe_b64encode(os.urandom(32))

# Derive a key from a password using PBKDF2 (not used in auto mode)
def derive_key_from_password(password: str, salt: bytes = None) -> bytes:
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Generate or load persistent RSA keypair from disk (auto mode)
def generate_rsa_keys(password: str = None) -> dict:
    priv_path = "rsa_private.pem"
    pub_path = "rsa_public.pem"
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        # Load existing keys from disk
        with open(priv_path, "rb") as f:
            private_bytes = f.read()
        with open(pub_path, "rb") as f:
            public_bytes = f.read()
    else:
        # Generate new RSA keypair and save to disk
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(priv_path, "wb") as f:
            f.write(private_bytes)
        with open(pub_path, "wb") as f:
            f.write(public_bytes)
    return {
        "private": private_bytes,
        "public": public_bytes
    }

def get_or_create_aes_key() -> bytes:
    key_path = "aes.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    key = base64.urlsafe_b64encode(os.urandom(32))
    with open(key_path, "wb") as f:
        f.write(key)
    return key
