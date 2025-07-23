# Crypto Communicator

A simple Python tool for encrypting and decrypting messages with different sensitivity levels.

## Features

- **Low sensitivity:** Base64 encoding (not secure, just encoding)
- **Medium sensitivity:** AES encryption (Fernet, 256-bit key)
- **High sensitivity:** RSA encryption (2048-bit keypair, persistent across sessions)

## Usage

1. Run the tool:

   ```
   python main.py
   ```

2. Follow the prompts:
   - Choose to encrypt or decrypt (`e` or `d`)
   - Choose sensitivity: low (`l`), medium (`m`), or high (`h`)
   - Enter your message

3. For medium and high sensitivity, keys are managed automatically and securely.  
   For high sensitivity, RSA keys are generated and stored in `rsa_private.pem` and `rsa_public.pem` for reuse.

## Requirements

- Python 3.7+
- `cryptography` library

Install dependencies with:

```
pip install -r requirements.txt
```

## Security Notes

- **Do not use this tool for real-world secrets without review.**
- Password-based key generation is not supported for RSA (high sensitivity) for security reasons.
- Key files (`rsa_private.pem`, `rsa_public.pem`) must be kept safe for decryption.

---

(C) 2025