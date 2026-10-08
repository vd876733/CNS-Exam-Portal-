import sys
import os
import copy
import time

# Ensure the parent directory is in the path so we can import models and security modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.packet import SecurePacket
from security.replay_protection import validate_packet_freshness

def simulate_replay_attack(original_packet: SecurePacket, delay_seconds: int = 0) -> dict:
    """
    Simulates a Replay Attack where an attacker captures a legitimate packet 
    over the network and blindly re-transmits it to the receiver.
    
    Because the attacker cannot forge the cryptographic signatures, they simply
    resend the exact same packet hoping the receiver will process the transaction twice
    (e.g., transferring $500 twice).
    
    Args:
        original_packet (SecurePacket): The initially transmitted, valid packet.
        delay_seconds (int): Optional delay before replaying to simulate timestamp expiration.
        
    Returns:
        dict: Containing the 'replayed_packet', the underlying 'validation_result', 
              and the exact 'ui_flow' strings for Streamlit.
    """
    # 1. Attacker copies the exact packet (they cannot modify it without breaking HMAC)
    replayed_packet = copy.deepcopy(original_packet)
    
    # 2. Simulate network/attacker delay if requested
    if delay_seconds > 0:
        time.sleep(delay_seconds)
        
    # 3. Submit to the receiver's security layer
    validation_result = validate_packet_freshness(
        transaction_id=replayed_packet.transaction_id,
        nonce=replayed_packet.nonce,
        timestamp=replayed_packet.timestamp
    )
    
    # 4. Generate the exact UI flow requested
    ui_flow = []
    
    if validation_result["status"] == "REPLAY ATTACK DETECTED":
        ui_flow.append("⚠️ REPLAY ATTACK")
        ui_flow.append("↓")
        
        if "Timestamp" in validation_result["reason"]:
            ui_flow.append("Expired timestamp detected")
        else:
            ui_flow.append("Duplicate transaction detected")
            
        ui_flow.append("↓")
        ui_flow.append("REQUEST REJECTED")
    else:
        # This shouldn't happen during a replay attack unless cache was cleared
        ui_flow.append("✅ VALID REQUEST")
        ui_flow.append("↓")
        ui_flow.append("Packet freshness verified")
        ui_flow.append("↓")
        ui_flow.append("REQUEST ACCEPTED")
        
    return {
        "replayed_packet": replayed_packet,
        "validation_result": validation_result,
        "ui_flow": ui_flow
    }

if __name__ == "__main__":
    print("--- Replay Attack Simulation ---")
    
    # 1. Setup a valid packet
    demo_packet = SecurePacket.create_new("Banking", "Alice", "Bob")
    demo_packet.ciphertext = "encrypted_transfer_$500"
    
    # 2. Process it once legitimately (this puts it in the replay cache)
    print("\n[!] Legitimate User sends the packet...")
    validate_packet_freshness(demo_packet.transaction_id, demo_packet.nonce, demo_packet.timestamp)
    
    # 3. Simulate the Replay Attack
    print("\n[!] Attacker intercepts and resends the exact same packet...")
    attack_results = simulate_replay_attack(demo_packet)
    
    print("\n--- UI Display Flow ---")
    for line in attack_results["ui_flow"]:
        print(line)
        
    print(f"\nUnderlying Reason: {attack_results['validation_result']['reason']}")
