import base64

def encrypt_base64(message: str) -> str:
    message_bytes = message.encode('utf-8')
    encoded_bytes = base64.b64encode(message_bytes)
    return encoded_bytes.decode('utf-8')

def decrypt_base64(encoded: str) -> str:
    encoded_bytes = encoded.encode('utf-8')
    message_bytes = base64.b64decode(encoded_bytes)
    return message_bytes.decode('utf-8')
