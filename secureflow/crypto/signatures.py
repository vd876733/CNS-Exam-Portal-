import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Union

# Importing for type hinting
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

"""
CRYPTOGRAPHIC CONCEPTS: ENCRYPTION vs. DIGITAL SIGNATURES

1. Encryption (Confidentiality):
   - You encrypt data with the receiver's PUBLIC KEY.
   - Only the receiver can decrypt it using their PRIVATE KEY.
   - Purpose: Ensuring no one else can read the message (Confidentiality).

2. Digital Signatures (Authentication & Non-Repudiation):
   - You "sign" (encrypt a hash of the data) with your own PRIVATE KEY.
   - Anyone can verify the signature using your PUBLIC KEY.
   - Purpose: Proving YOU sent the message (Authenticity) and it hasn't 
     been altered (Integrity). You cannot later deny sending it (Non-Repudiation).
"""

def sign_data(data: Union[str, bytes], private_key: RSAPrivateKey) -> str:
    """
    Signs the data using the sender's RSA private key.
    Uses RSA-PSS with SHA-256 (a modern, highly secure padding scheme).
    
    Args:
        data (str | bytes): Data to sign.
        private_key (RSAPrivateKey): The sender's private key.
        
    Returns:
        str: Base64 encoded digital signature.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Return base64 so it can be easily displayed in the UI later
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data: Union[str, bytes], signature_b64: str, public_key: RSAPublicKey) -> bool:
    """
    Verifies a digital signature using the sender's RSA public key.
    
    Args:
        data (str | bytes): The original data to verify against.
        signature_b64 (str): The base64 encoded signature.
        public_key (RSAPublicKey): The sender's public key.
        
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        signature = base64.b64decode(signature_b64)
        
        # verify() will raise InvalidSignature if the verification fails
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # If we reach here, no exception was thrown, so the signature is valid.
        return True 
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False

# Unit-test example demonstrating the flow
if __name__ == "__main__":
    import sys
    import os
    # Add parent dir to path so we can import rsa.py for testing
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from crypto.rsa import generate_rsa_key_pair
    
    print("--- RSA Digital Signature Demonstration ---")
    
    # 1. Generate keys (Sender)
    print("\n[!] Generating RSA-2048 Key Pair...")
    sender_private_key, sender_public_key = generate_rsa_key_pair()
    
    original_message = "Electronic Prescription: Amoxicillin 500mg"
    print(f"\n[+] Original Message: '{original_message}'")
    
    # 2. Sign the data (Sender)
    print("[!] Sender is signing the message with their PRIVATE KEY...")
    signature = sign_data(original_message, sender_private_key)
    print(f"[+] Signature (Base64): {signature[:50]}...")
    
    # 3. Verify valid signature (Receiver)
    print("\n[!] Receiver is verifying the signature with sender's PUBLIC KEY...")
    is_valid = verify_signature(original_message, signature, sender_public_key)
    if is_valid:
        print("[✓] SUCCESS: Signature is valid. Data is from sender and unaltered.")
    else:
        print("[✗] ERROR: Signature is invalid.")
        
    # 4. Attack Simulation: Tampering
    print("\n--- Attack Simulation: Tampering ---")
    modified_message = "Electronic Prescription: Oxycodone 500mg"
    print(f"[-] Attacker modifies message in transit to: '{modified_message}'")
    
    print("[!] Receiver Verifying Modified Message against Original Signature...")
    is_valid_attack = verify_signature(modified_message, signature, sender_public_key)
    if not is_valid_attack:
        print("[✓] SUCCESS: Verification correctly FAILED. Tampering detected!")
    else:
        print("[✗] ERROR: Verification incorrectly succeeded on tampered data.")
