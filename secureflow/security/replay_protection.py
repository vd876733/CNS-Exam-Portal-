import time

# ==========================================
# IN-MEMORY REPLAY CACHE
# ==========================================
# In a real system, this would be a fast distributed cache like Redis.
# For this classroom demonstration, a simple in-memory set is perfect.
_PROCESSED_NONCES = set()
_PROCESSED_TX_IDS = set()

# Packets older than this window (in seconds) are immediately rejected,
# keeping the cache size manageable in a real system.
MAX_TIMESTAMP_AGE_SECONDS = 60 
# ==========================================

def validate_packet_freshness(transaction_id: str, nonce: str, timestamp: float) -> dict:
    """
    Validates that a packet is fresh and has not been maliciously intercepted 
    and re-sent (replayed) by an attacker.
    
    Args:
        transaction_id (str): The unique ID of the packet.
        nonce (str): The cryptographic Number Used Once.
        timestamp (float): The Unix timestamp when the packet was generated.
        
    Returns:
        dict: Containing 'status' (VALID REQUEST or REPLAY ATTACK DETECTED) and 'reason'.
    """
    current_time = time.time()
    
    # 1. Check Timestamp: Prevents an attacker from holding a packet for hours and replaying it.
    age = current_time - timestamp
    if age > MAX_TIMESTAMP_AGE_SECONDS:
        return {
            "status": "REPLAY ATTACK DETECTED", 
            "reason": f"Timestamp expired. Packet is {age:.1f} seconds old (Limit: {MAX_TIMESTAMP_AGE_SECONDS}s)."
        }
    
    # Also prevent packets claiming to be from the future
    if age < -5: # 5 seconds of clock skew allowed
        return {
            "status": "REPLAY ATTACK DETECTED", 
            "reason": "Timestamp is in the future. Possible clock tampering."
        }
        
    # 2. Check Transaction ID: Ensures this exact transmission hasn't been processed
    if transaction_id in _PROCESSED_TX_IDS:
        return {
            "status": "REPLAY ATTACK DETECTED", 
            "reason": f"Reused Transaction ID: {transaction_id}"
        }
        
    # 3. Check Nonce: A secondary cryptographic check that the exact cryptographic payload is unique
    if nonce in _PROCESSED_NONCES:
        return {
            "status": "REPLAY ATTACK DETECTED", 
            "reason": f"Reused Nonce: {nonce}"
        }
        
    # 4. If all checks pass, record the nonce and tx_id in the cache 
    # to block any future replays of this exact packet.
    _PROCESSED_TX_IDS.add(transaction_id)
    _PROCESSED_NONCES.add(nonce)
    
    return {
        "status": "VALID REQUEST", 
        "reason": "Packet is fresh and unique."
    }

def clear_cache():
    """Helper function to clear the cache during interactive Streamlit testing."""
    _PROCESSED_NONCES.clear()
    _PROCESSED_TX_IDS.clear()


if __name__ == "__main__":
    import uuid
    from nonce import generate_nonce
    
    print("--- Replay Protection Demonstration ---")
    
    # Setup fresh packet data
    tx_id = str(uuid.uuid4())
    packet_nonce = generate_nonce()
    packet_timestamp = time.time()
    
    print("\n[!] Processing Packet for the FIRST time (Legitimate User)...")
    result1 = validate_packet_freshness(tx_id, packet_nonce, packet_timestamp)
    print(f"Status: {result1['status']} -> {result1['reason']}")
    
    print("\n--- Attack Simulation: Replay Attack ---")
    print("[-] Attacker intercepts the packet and immediately resends it...")
    result2 = validate_packet_freshness(tx_id, packet_nonce, packet_timestamp)
    print(f"Status: {result2['status']} -> {result2['reason']}")
    
    print("\n--- Attack Simulation: Delayed Replay ---")
    print("[-] Attacker intercepts a packet, waits 65 seconds, and resends it...")
    stale_timestamp = time.time() - 65
    fresh_tx_id = str(uuid.uuid4())
    fresh_nonce = generate_nonce()
    result3 = validate_packet_freshness(fresh_tx_id, fresh_nonce, stale_timestamp)
    print(f"Status: {result3['status']} -> {result3['reason']}")
