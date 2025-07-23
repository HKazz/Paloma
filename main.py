from sensitivity_handler import get_encryption_pair

def main():
    print("=== Data Protection Tool ===")
    
    # Ask user if they want to encrypt or decrypt
    operation = input("Do you want to encrypt or decrypt? (e/d): ").strip().lower()
    if operation in ("e", "encrypt"):
        operation = "encrypt"
    elif operation in ("d", "decrypt"):
        operation = "decrypt"
    else:
        print("Invalid operation. Please enter 'encrypt' (e) or 'decrypt' (d).")
        return

    # Ask user for sensitivity level
    sensitivity = input("Enter sensitivity level ((l)ow / (m)edium / (h)igh): ").strip().lower()
    if sensitivity in ("l", "low"):
        sensitivity = "low"
    elif sensitivity in ("m", "medium"):
        sensitivity = "medium"
    elif sensitivity in ("h", "high"):
        sensitivity = "high"
    else:
        print("Invalid sensitivity level. Please enter 'low' (l), 'medium' (m), or 'high' (h).")
        return

    key_mode = None
    password = None
    # Only medium and high sensitivity require a key, but only auto mode is supported
    if sensitivity in ("medium", "high"):
        key_mode = "auto"
        password = None

    # Get encryption/decryption functions for the chosen sensitivity
    try:
        encrypt_func, decrypt_func = get_encryption_pair(sensitivity, key_mode, password)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Perform encryption or decryption
    if operation == "encrypt":
        message = input("Enter message to encrypt: ")
        result = encrypt_func(message)
        print(f"\n🔐 Encrypted message:\n{result}")
    else:
        ciphertext = input("Enter message to decrypt: ")
        try:
            result = decrypt_func(ciphertext)
            print(f"\n🔓 Decrypted message:\n{result}")
        except Exception as e:
            print(f"\n❌ Decryption failed: {e}")

if __name__ == "__main__":
    main()
