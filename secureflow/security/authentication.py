import hashlib
import secrets
import hmac

"""
EDUCATIONAL DEMONSTRATION ONLY
------------------------------
This module demonstrates the concept of secure password hashing for authentication.
It does NOT represent a production-grade identity provider for healthcare, banking,
or enterprise systems. It uses an in-memory dummy database solely for the purpose 
of visualizing the authentication step in the SecureFlow pipeline.
"""

def _hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Hashes a password using PBKDF2 with HMAC-SHA256.
    Returns the salt and the resulting hash.
    """
    if salt is None:
        # Generate a secure random salt (16 bytes)
        salt = secrets.token_bytes(16)
        
    # PBKDF2 is a standard key derivation function that is intentionally slow.
    # The high iteration count protects against brute-force and dictionary attacks.
    pwd_hash = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password.encode('utf-8'), 
        salt=salt, 
        iterations=100000 
    )
    return salt, pwd_hash

# ==========================================
# DUMMY DATABASE INITIALIZATION
# ==========================================
# In a real database, you store the username, the SALT, and the HASH. 
# You NEVER store the plaintext password.

_alice_salt, _alice_hash = _hash_password("password123")
_bob_salt, _bob_hash = _hash_password("secure456")

DUMMY_DATABASE = {
    "Alice": {"salt": _alice_salt, "hash": _alice_hash},
    "Bob": {"salt": _bob_salt, "hash": _bob_hash}
}
# ==========================================


def authenticate_user(username: str, password: str) -> dict:
    """
    Authenticates a user by hashing the provided password with the user's stored salt
    and securely comparing the resulting hash with the stored hash.
    
    Args:
        username (str): The username.
        password (str): The provided plaintext password.
        
    Returns:
        dict: A dictionary containing 'success' (bool) and a 'message' (str).
    """
    if username not in DUMMY_DATABASE:
        return {"success": False, "message": "User not found"}
        
    stored_record = DUMMY_DATABASE[username]
    stored_salt = stored_record["salt"]
    stored_hash = stored_record["hash"]
    
    # Hash the provided password using the retrieved salt
    _, provided_hash = _hash_password(password, stored_salt)
    
    # CRITICAL: Securely compare the hashes using constant-time comparison 
    # to prevent timing attacks.
    if hmac.compare_digest(stored_hash, provided_hash):
        return {"success": True, "message": "Identity authenticated"}
    else:
        return {"success": False, "message": "Invalid credentials"}

if __name__ == "__main__":
    import time
    
    print("--- SecureFlow Authentication Demonstration ---")
    
    # 1. Valid Login Simulation
    print("\n[Simulating Alice logging in with correct password]")
    print("Authenticating...")
    time.sleep(1)
    
    result = authenticate_user("Alice", "password123")
    
    # The UI will use this step-by-step logic
    print("↓")
    print("Credentials verified")
    time.sleep(0.5)
    print("↓")
    if result["success"]:
        print(f"{result['message']} (Welcome, Alice!)")
    
    
    # 2. Invalid Login Simulation
    print("\n[Simulating Alice logging in with WRONG password]")
    print("Authenticating...")
    time.sleep(1)
    
    result_fail = authenticate_user("Alice", "hacker123")
    print("↓")
    if not result_fail["success"]:
        print(f"Authentication Failed: {result_fail['message']}")
