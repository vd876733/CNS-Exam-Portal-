from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key_pair():
    """
    Generates a modern, secure RSA key pair.
    
    Returns:
        tuple: (private_key, public_key)
        
    Note: For this educational prototype, the private key is kept strictly in memory 
    and is not serialized to disk. This mimics hardware-backed keys where the
    private material never leaves the secure enclave.
    """
    # 2048-bit is a modern, secure standard for RSA.
    # 65537 is the standard secure public exponent (F4).
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
    )
    
    # Derive the public key from the private key
    public_key = private_key.public_key()
    
    return private_key, public_key
