import secrets

def generate_nonce(length: int = 16) -> str:
    """
    Generates a cryptographically secure random nonce (Number Used Once).
    
    A nonce ensures that even if the exact same plaintext is sent twice 
    with the exact same key, the resulting ciphertext will be entirely different.
    This also provides a unique fingerprint for the packet to prevent replay attacks.
    
    Args:
        length (int): Length of the random bytes.
        
    Returns:
        str: A secure random hexadecimal string (e.g., 32 characters long).
    """
    return secrets.token_hex(length)
