from encryptor import (
    encrypt_base64, decrypt_base64,
    encrypt_aes, decrypt_aes,
    encrypt_rsa, decrypt_rsa
)
from key_generator import get_or_create_aes_key, generate_rsa_keys
from cryptography.hazmat.primitives import serialization

# Store keys for session (in-memory)
KEY_STORE = {}

# Decide which encryption/decryption functions to use based on sensitivity
def get_encryption_pair(sensitivity: str, key_mode: str = None, password: str = None):
    sensitivity = sensitivity.lower()

    if sensitivity == "low":
        # Base64 does not require a key
        return encrypt_base64, decrypt_base64

    elif sensitivity == "medium":
        key = get_or_create_aes_key()  # Always use the persistent key
        return lambda msg: encrypt_aes(msg, key), lambda msg: decrypt_aes(msg, key)

    elif sensitivity == "high":
        keys = generate_rsa_keys()
        public_key = serialization.load_pem_public_key(keys["public"])
        private_key = serialization.load_pem_private_key(keys["private"], password=None)
        return (
            lambda msg: encrypt_rsa(msg, public_key),
            lambda msg: decrypt_rsa(msg, private_key)
        )

    else:
        raise ValueError("Invalid sensitivity level")
