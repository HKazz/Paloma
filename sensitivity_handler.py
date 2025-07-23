from encryptor import (
    encrypt_aes, decrypt_aes,
    encrypt_rsa, decrypt_rsa,
    encrypt_base64, decrypt_base64
)
from key_generator import generate_rsa_keys, generate_aes_key, derive_key_from_password
from cryptography.hazmat.primitives import serialization

# Store keys for session (in-memory)
KEY_STORE = {}

# Decide which encryption/decryption functions to use based on sensitivity
def get_encryption_pair(sensitivity: str, key_mode: str, password: str = None):
    sensitivity = sensitivity.lower()

    if sensitivity == "low":
        # Base64 does not require a key
        return encrypt_base64, decrypt_base64

    elif sensitivity == "medium":
        key = get_key("aes", key_mode, password)
        return lambda msg: encrypt_aes(msg, key), lambda msg: decrypt_aes(msg, key)

    elif sensitivity == "high":
        keys = get_rsa_keys(key_mode, password)
        public_key = serialization.load_pem_public_key(keys["public"])
        private_key = serialization.load_pem_private_key(keys["private"], password=None)
        return (
            lambda msg: encrypt_rsa(msg, public_key),
            lambda msg: decrypt_rsa(msg, private_key)
        )

    else:
        raise ValueError("Unknown sensitivity level")

# Get or generate a symmetric key for AES
def get_key(algorithm: str, mode: str, password: str = None):
    key_id = f"{algorithm}_{mode}_{password}"

    if key_id in KEY_STORE:
        return KEY_STORE[key_id]

    if mode == "password":
        if not password:
            raise ValueError("Password is required in password mode")
        key = derive_key_from_password(password)
    elif mode == "auto":
        key = generate_aes_key()
    else:
        raise ValueError("Invalid key mode")

    KEY_STORE[key_id] = key
    return key

# Get or generate an RSA keypair (auto mode only)
def get_rsa_keys(mode: str, password: str = None):
    key_id = f"rsa_keys_{mode}_{password}"
    if key_id in KEY_STORE:
        return KEY_STORE[key_id]

    if mode == "password":
        keys = generate_rsa_keys(password)
    else:
        keys = generate_rsa_keys()
    KEY_STORE[key_id] = keys
    return keys
