# test.py - Simple Cryptography Test
from cryptography.fernet import Fernet

def test_encryption():
    # Generate a key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Test encryption/decryption
    message = b"Hello, this is a test message"
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    
    print("✅ Cryptography test successful!")
    print(f"Original: {message.decode()}")
    print(f"Encrypted: {encrypted.decode()}")
    print(f"Decrypted: {decrypted.decode()}")
    
    assert decrypted == message, "Decryption failed!"
    return True

if __name__ == "__main__":
    test_encryption()