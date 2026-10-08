import time

"""
EDUCATIONAL DEMONSTRATION ONLY
------------------------------
This module demonstrates the concept of Rate Limiting.
In the context of the CIA Triad (Confidentiality, Integrity, Availability), 
rate limiting protects **Availability** by preventing Denial-of-Service (DoS) 
attacks, spam, or password brute-forcing attempts.
"""

# ==========================================
# IN-MEMORY RATE LIMIT CACHE
# ==========================================
# In a real system, this would be backed by Redis or Memcached.
# Dictionary format: {"user_id": [timestamp1, timestamp2, ...]}
_REQUEST_HISTORY = {}
# ==========================================

def check_rate_limit(user_id: str, max_requests: int = 5, window_seconds: int = 10) -> dict:
    """
    Checks if a user has exceeded the allowed number of requests within a given time window.
    Uses a simple "sliding log" algorithm for educational purposes.
    
    Args:
        user_id (str): The identifier of the user (e.g., username or IP address).
        max_requests (int): Maximum allowed requests in the time window.
        window_seconds (int): The time window in seconds.
        
    Returns:
        dict: Containing 'status' ('allowed' or 'rate limit exceeded') and a 'message'.
    """
    current_time = time.time()
    
    # Initialize user history if this is their first request
    if user_id not in _REQUEST_HISTORY:
        _REQUEST_HISTORY[user_id] = []
        
    # Retrieve the user's past request timestamps
    history = _REQUEST_HISTORY[user_id]
    
    # Filter out timestamps that are older than the time window
    # (Keep only requests made within the recent window)
    recent_requests = [ts for ts in history if (current_time - ts) <= window_seconds]
    
    # Check if the number of recent requests meets or exceeds the limit
    if len(recent_requests) >= max_requests:
        # Save the cleaned-up history back to the dictionary
        _REQUEST_HISTORY[user_id] = recent_requests
        return {
            "status": "rate limit exceeded",
            "message": f"Availability Protection: User '{user_id}' exceeded limit of {max_requests} requests per {window_seconds}s."
        }
        
    # If the limit is not reached, record this new request
    recent_requests.append(current_time)
    _REQUEST_HISTORY[user_id] = recent_requests
    
    return {
        "status": "allowed",
        "message": "Request allowed."
    }

def reset_rate_limits():
    """
    Clears the in-memory rate limit cache.
    This is highly useful for the Streamlit UI, allowing the evaluator 
    to easily reset the state and try different scenarios.
    """
    _REQUEST_HISTORY.clear()
    
# Unit-test example demonstrating the flow
if __name__ == "__main__":
    print("--- SecureFlow Availability Protection (Rate Limiter) ---")
    
    demo_user = "Alice"
    limit = 3
    window = 5 # seconds
    
    print(f"\n[!] Simulating rapid requests (Max {limit} requests per {window}s for user {demo_user})")
    
    # Simulate a user or bot clicking a button rapidly 5 times
    for i in range(1, 6):
        result = check_rate_limit(demo_user, max_requests=limit, window_seconds=window)
        if result['status'] == 'allowed':
            print(f"Request {i}: [✓] {result['status'].upper()}")
        else:
            print(f"Request {i}: [✗] {result['status'].upper()} -> {result['message']}")
            
    print(f"\n[!] Waiting for {window} seconds for the time window to clear...")
    time.sleep(window)
    
    # Try again after waiting
    result = check_rate_limit(demo_user, max_requests=limit, window_seconds=window)
    if result['status'] == 'allowed':
        print(f"Request 6 (After Wait): [✓] {result['status'].upper()}")
