import hashlib
from typing import Union

def hash_data(data: Union[str, bytes]) -> str:
    """
    Generates a SHA-256 hash for the given data.
    
    IMPORTANT NOTE ON HASHING VS ENCRYPTION:
    Hashing is a one-way mathematical function. It takes an input of any size
    and produces a fixed-size string (digest). It is NOT encryption. 
    You cannot "decrypt" a hash back to its original data. It is primarily 
    used for verifying data integrity (checking if data was tampered with).
    
    Args:
        data (str | bytes): The data to be hashed.
        
    Returns:
        str: A hexadecimal representation of the SHA-256 digest.
    """
    # Safely handle both strings and bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise TypeError("Data must be either a string or bytes.")
        
    # Initialize the SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the data
    sha256_hash.update(data)
    
    # Return the hexadecimal digest (e.g., 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e')
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    print("--- SHA-256 Hashing Demonstration ---")
    
    input_message = "Confidential Information: Patient John Doe"
    print(f"Original Input: '{input_message}'\n")
    
    # 1. Generate first hash
    hash_result_1 = hash_data(input_message)
    print(f"SHA-256 Hash 1: {hash_result_1}")
    
    # 2. Generate second hash from the exact same input
    hash_result_2 = hash_data(input_message)
    print(f"SHA-256 Hash 2: {hash_result_2}")
    
    # 3. Verify they match
    if hash_result_1 == hash_result_2:
        print("\n[✓] SUCCESS: The same input predictably produces the exact same hash.")
    else:
        print("\n[✗] ERROR: Hashes do not match.")
        
    print("\nNote: This process is entirely one-way. You cannot mathematically reverse")
    print(f"the hash '{hash_result_1[:10]}...' to get back '{input_message}'.")
