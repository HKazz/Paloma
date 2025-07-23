import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# === Base64 Encryption (LOW sensitivity) ===
def encrypt_base64(message: str) -> str:
    # Encode message as base64 (not secure, just encoding)
    return base64.b64encode(message.encode()).decode()

def decrypt_base64(ciphertext: str) -> str:
    # Decode base64-encoded message
    return base64.b64decode(ciphertext.encode()).decode()


# === AES Encryption with Fernet (MEDIUM sensitivity) ===
def encrypt_aes(message: str, key: bytes) -> str:
    # Encrypt message using Fernet (AES)
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    return cipher.encrypt(message.encode()).decode()

def decrypt_aes(ciphertext: str, key: bytes) -> str:
    # Decrypt message using Fernet (AES)
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    return cipher.decrypt(ciphertext.encode()).decode()


# === RSA Encryption (HIGH sensitivity) ===
def encrypt_rsa(message: str, public_key) -> str:
    # Encrypt message using RSA public key
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_rsa(ciphertext: str, private_key) -> str:
    # Decrypt message using RSA private key
    decrypted = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()
