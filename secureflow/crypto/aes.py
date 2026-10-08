import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def generate_key() -> bytes:
    """
    Generates a secure random 256-bit (32 bytes) key for AES-256.
    """
    # AESGCM.generate_key(bit_length=256) uses os.urandom securely
    return AESGCM.generate_key(bit_length=256)

def encrypt_data(plaintext: str, key: bytes) -> dict:
    """
    Encrypts the plaintext using AES-256-GCM.
    
    Args:
        plaintext (str): The data to encrypt.
        key (bytes): The 256-bit AES key.
        
    Returns:
        dict: A dictionary containing base64 encoded ciphertext and nonce,
              which is easily displayable in the Streamlit UI.
    """
    try:
        # Initialize AES-GCM with the 256-bit key
        aesgcm = AESGCM(key)
        
        # Generate a secure random 96-bit (12 bytes) nonce (standard for GCM)
        nonce = os.urandom(12)
        
        # Convert plaintext string to bytes for encryption
        data = plaintext.encode('utf-8')
        
        # Encrypt the data. 
        # AES-GCM automatically computes and appends the 16-byte authentication tag 
        # to the end of the ciphertext.
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
        
        # Return base64 encoded strings for easy visualization without encoding errors
        return {
            "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce_b64": base64.b64encode(nonce).decode('utf-8')
        }
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_data(ciphertext_b64: str, key: bytes, nonce_b64: str) -> str:
    """
    Decrypts the AES-256-GCM encrypted data.
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext (including auth tag).
        key (bytes): The 256-bit AES key used for encryption.
        nonce_b64 (str): Base64 encoded nonce used for encryption.
        
    Returns:
        str: The decrypted original plaintext.
        
    Raises:
        ValueError: If the key is invalid, or if the ciphertext has been tampered with.
    """
    try:
        # Initialize AES-GCM
        aesgcm = AESGCM(key)
        
        # Decode the base64 inputs back to bytes
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        
        # Decrypt and verify the authentication tag simultaneously
        # This will raise an InvalidTag exception if the ciphertext is modified
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        
        # Convert bytes back to string
        return plaintext_bytes.decode('utf-8')
        
    except InvalidTag:
        # This is where Authenticated Encryption proves its value.
        raise ValueError("Decryption failed: Ciphertext has been tampered with or key is incorrect (Invalid Tag).")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# Unit-test example demonstrating the flow
if __name__ == "__main__":
    print("--- AES-256-GCM Demonstration ---")
    
    original_plaintext = "Transfer $1,000,000 from Account A to Account B"
    print(f"1. Original Plaintext: '{original_plaintext}'")
    
    # 1. Generate Key
    key = generate_key()
    key_b64 = base64.b64encode(key).decode('utf-8')
    print(f"2. Generated 256-bit Key (Base64): {key_b64}")
    
    # 2. Encrypt
    print("\n[!] Encrypting data...")
    encrypted_payload = encrypt_data(original_plaintext, key)
    print(f"3. Generated Nonce (Base64): {encrypted_payload['nonce_b64']}")
    print(f"4. Ciphertext (Base64):      {encrypted_payload['ciphertext_b64']}")
    
    # 3. Decrypt
    print("\n[!] Decrypting data...")
    decrypted_plaintext = decrypt_data(
        encrypted_payload['ciphertext_b64'], 
        key, 
        encrypted_payload['nonce_b64']
    )
    print(f"5. Decrypted Plaintext: '{decrypted_plaintext}'")
    
    # 4. Demonstrate Tampering Protection (Authenticated Encryption)
    print("\n--- Attack Simulation: Tampering ---")
    print("Attempting to decrypt with a modified ciphertext...")
    
    # Tamper with the ciphertext by flipping a bit
    tampered_ciphertext = encrypted_payload['ciphertext_b64']
    # Change a character in the middle of the base64 string
    mid = len(tampered_ciphertext) // 2
    # Replace character with 'A' (or 'B' if it was already 'A')
    replacement = 'B' if tampered_ciphertext[mid] == 'A' else 'A'
    tampered_ciphertext = tampered_ciphertext[:mid] + replacement + tampered_ciphertext[mid+1:]
    
    try:
        decrypt_data(tampered_ciphertext, key, encrypted_payload['nonce_b64'])
        print("[-] Decryption succeeded (This shouldn't happen!)")
    except ValueError as e:
        print(f"[+] Decryption correctly failed.\n    Reason: {e}")
