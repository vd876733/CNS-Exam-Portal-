from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

"""
CRYPTOGRAPHIC CONCEPT: DIFFIE-HELLMAN KEY EXCHANGE

Diffie-Hellman (DH) is a mathematical method used securely to establish a shared 
secret between two parties over an untrusted, public network (like the internet).

IMPORTANT:
- DH does NOT encrypt application data itself. 
- It only establishes the shared secret.
- Once the shared secret is established, it is passed through a Key Derivation
  Function (KDF) to generate a symmetric key (like an AES-256 key).
- That derived AES key is then used for actual data encryption (Confidentiality) 
  and HMAC (Integrity).
"""

def generate_dh_parameters() -> dh.DHParameters:
    """
    Generates DH domain parameters (the prime and generator). 
    Both parties (Sender and Receiver) must agree on these parameters before 
    generating their keys.
    
    Note: Generating 2048-bit parameters can take a few seconds. In production,
    standardized secure groups (e.g., RFC 3526) are usually pre-generated.
    """
    # 2048-bit is a modern, secure standard for DH modulus size
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_key_pair(parameters: dh.DHParameters):
    """
    Generates a private and public key pair for a party.
    
    Args:
        parameters (dh.DHParameters): The agreed-upon DH domain parameters.
        
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
    """
    Derives the raw shared secret by mathematically combining a party's own 
    private key with the peer's public key.
    
    Args:
        private_key (dh.DHPrivateKey): The party's own private key. (NEVER SHARED)
        peer_public_key (dh.DHPublicKey): The peer's public key. (SENT OVER NETWORK)
        
    Returns:
        bytes: The raw shared secret.
    """
    return private_key.exchange(peer_public_key)

def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derives a secure AES-256 session key (32 bytes) from the raw shared secret
    using HKDF (HMAC-based Extract-and-Expand Key Derivation Function) with SHA-256.
    
    Raw DH secrets are not perfectly uniformly distributed, so passing them 
    through a KDF is a required security practice before using them as AES keys.
    
    Args:
        shared_secret (bytes): The raw shared secret from the DH exchange.
        
    Returns:
        bytes: A secure 32-byte symmetric session key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # We need a 256-bit (32 bytes) key for AES-256
        salt=None, # For this prototype we omit salt; in production, use a secure salt
        info=b'secureflow_session_key', # Context information
    )
    return hkdf.derive(shared_secret)

def get_key_fingerprint(key: bytes) -> str:
    """
    Returns a shortened, printable fingerprint of a key for UI display.
    This safely allows visual confirmation in Streamlit that both parties 
    derived the exact same key without exposing the full secret material.
    
    Args:
        key (bytes): The raw bytes of the key.
        
    Returns:
        str: A shortened hex string (e.g., '1a2b3c...8y9z')
    """
    hex_key = key.hex()
    return f"{hex_key[:8]}...{hex_key[-8:]}"

# Unit-test example demonstrating the flow
if __name__ == "__main__":
    import time
    
    print("--- Diffie-Hellman Key Exchange Demonstration ---")
    
    # 1. Parameter Agreement
    print("\n[!] Generating DH Parameters (This may take a few seconds)...")
    start_time = time.time()
    shared_parameters = generate_dh_parameters()
    print(f"[+] Parameters generated in {time.time() - start_time:.2f} seconds.")
    
    # 2. Key Generation
    print("\n[!] Generating Key Pairs...")
    # SENDER (Alice)
    sender_private, sender_public = generate_key_pair(shared_parameters)
    # RECEIVER (Bob)
    receiver_private, receiver_public = generate_key_pair(shared_parameters)
    
    print("\n[+] Both parties hold their own PRIVATE keys securely.")
    print("[+] They exchange their PUBLIC keys over the untrusted network.")
    
    # 3. Exchange & Derive Shared Secret
    print("\n[!] Deriving Shared Secrets mathematically...")
    
    # Sender computes secret using Sender's Private + Receiver's Public
    sender_shared_secret = derive_shared_secret(sender_private, receiver_public)
    
    # Receiver computes secret using Receiver's Private + Sender's Public
    receiver_shared_secret = derive_shared_secret(receiver_private, sender_public)
    
    # 4. Derive AES Session Keys
    print("\n[!] Passing raw secrets through HKDF to generate AES-256 session keys...")
    sender_aes_key = derive_session_key(sender_shared_secret)
    receiver_aes_key = derive_session_key(receiver_shared_secret)
    
    # 5. Verification
    print("\n--- Final Verification ---")
    print(f"Sender's Derived Key Fingerprint:   {get_key_fingerprint(sender_aes_key)}")
    print(f"Receiver's Derived Key Fingerprint: {get_key_fingerprint(receiver_aes_key)}")
    
    if sender_aes_key == receiver_aes_key:
        print("\n[✓] SUCCESS: Both parties mathematically derived the exact same 256-bit AES key!")
        print("    They can now use this key for AES-GCM encryption and HMAC-SHA256,")
        print("    even though the key was never transmitted across the network.")
    else:
        print("\n[✗] ERROR: Keys do not match.")
