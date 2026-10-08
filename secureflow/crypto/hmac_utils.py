import hmac
import hashlib
from typing import Union

def generate_hmac(data: Union[str, bytes], key: bytes) -> str:
    """
    Generates an HMAC-SHA256 signature for the given data using a secret key.
    
    This ensures both data integrity (the data hasn't changed) and 
    authenticity (the data came from someone holding the secret key).
    
    Args:
        data (str | bytes): The data to authenticate.
        key (bytes): The shared secret key. (CRITICAL: MUST NEVER BE EXPOSED IN UI)
        
    Returns:
        str: A hexadecimal representation of the HMAC.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise TypeError("Data must be either a string or bytes.")
        
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be bytes.")
        
    if len(key) == 0:
        raise ValueError("HMAC key cannot be empty.")

    # Create a new hmac object using the key and SHA256 as the digest algorithm
    h = hmac.new(key, data, hashlib.sha256)
    
    # Return the hexadecimal digest
    return h.hexdigest()

def verify_hmac(data: Union[str, bytes], key: bytes, expected_hmac: str) -> bool:
    """
    Verifies if the provided expected_hmac matches the data and key.
    
    Args:
        data (str | bytes): The data to authenticate.
        key (bytes): The shared secret key.
        expected_hmac (str): The hexadecimal HMAC to verify against.
        
    Returns:
        bool: True if authentic, False otherwise.
    """
    try:
        # Re-calculate the HMAC for the given data and key
        calculated_hmac = generate_hmac(data, key)
        
        # CRITICAL: Use constant-time comparison to prevent timing attacks.
        # Attackers can guess hashes byte-by-byte if standard string comparison (==) is used,
        # because standard comparison fails early and takes different amounts of time 
        # depending on where the mismatch occurs.
        return hmac.compare_digest(calculated_hmac, expected_hmac)
    except Exception as e:
        # In a real system, log this securely.
        print(f"HMAC verification error: {str(e)}")
        return False

# Unit-test example demonstrating the flow
if __name__ == "__main__":
    import os
    
    print("--- HMAC-SHA256 Demonstration ---")
    
    # 1. Setup
    original_message = "Valid Banking Transaction: Transfer $50"
    # Generate a random secret key for demonstration 
    # (In SecureFlow, this will come from Diffie-Hellman)
    secret_key = os.urandom(32) 
    
    print(f"[+] Original Message: '{original_message}'")
    
    # 2. Generate HMAC
    print("\n[!] Generating HMAC...")
    mac = generate_hmac(original_message, secret_key)
    print(f"[+] Generated HMAC: {mac}")
    
    # 3. Verify valid message
    print("\n[!] Verifying Original Message...")
    is_valid = verify_hmac(original_message, secret_key, mac)
    if is_valid:
        print("[✓] SUCCESS: HMAC matches. Data is authentic and intact.")
    else:
        print("[✗] ERROR: HMAC verification failed for original message.")
        
    # 4. Attack Simulation: Tamper with data
    print("\n--- Attack Simulation: Tampering ---")
    modified_message = "Valid Banking Transaction: Transfer $950"
    print(f"[-] Attacker modifies message in transit to: '{modified_message}'")
    
    print("[!] Receiver Verifying Modified Message against Original HMAC...")
    is_valid_attack = verify_hmac(modified_message, secret_key, mac)
    if not is_valid_attack:
        print("[✓] SUCCESS: Verification correctly FAILED. Tampering detected!")
    else:
        print("[✗] ERROR: Verification incorrectly succeeded on tampered data.")
