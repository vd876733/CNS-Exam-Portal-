import random
import sys
import os

# Ensure the parent directory is in the path so we can import the models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.packet import SecurePacket

def simulate_tampering(packet: SecurePacket) -> dict:
    """
    Simulates a Man-in-the-Middle (MITM) tampering attack where an attacker
    intercepts the packet in transit and modifies the encrypted data without
    knowing the decryption key.
    
    In this educational simulation, the attacker flips a character in the base64 
    ciphertext, hoping to change the underlying plaintext (e.g., changing 
    "Transfer $10" to "Transfer $90"). Because we implemented AES-GCM and HMAC,
    the receiver will detect this tampering immediately.
    
    Args:
        packet (SecurePacket): The intercepted packet.
        
    Returns:
        dict: A dictionary containing the 'tampered_packet' and an 'attack_log'.
    """
    # Create a log to display in the Streamlit UI
    attack_log = [
        "[ATTACKER] 🚨 Packet intercepted in transit on untrusted network.",
        f"[ATTACKER] 🎯 Target Transaction ID: {packet.transaction_id}",
        "[ATTACKER] 🛠️ Attempting to blindly modify ciphertext without the AES key..."
    ]
    
    if not packet.ciphertext:
        attack_log.append("[ATTACKER] ❌ Failure: No ciphertext found in packet to tamper with.")
        return {"tampered_packet": packet, "attack_log": attack_log}

    try:
        # The ciphertext is stored as a base64 string. 
        # We will alter a character in the middle of the string to simulate bit-flipping.
        original_ciphertext = packet.ciphertext
        
        # Pick a random index in the middle of the string
        if len(original_ciphertext) > 5:
            mid_start = len(original_ciphertext) // 4
            mid_end = len(original_ciphertext) - mid_start
            tamper_idx = random.randint(mid_start, mid_end)
        else:
            tamper_idx = 0
            
        # Flip the character (e.g., if 'A' make it 'B', else 'A')
        char_to_flip = original_ciphertext[tamper_idx]
        new_char = 'B' if char_to_flip == 'A' else 'A'
        
        # Construct the tampered ciphertext
        tampered_ciphertext = (
            original_ciphertext[:tamper_idx] + 
            new_char + 
            original_ciphertext[tamper_idx + 1:]
        )
        
        # Apply the tampered ciphertext back to the packet
        packet.ciphertext = tampered_ciphertext
        
        attack_log.append(f"[ATTACKER] ✅ Success: Blindly modified ciphertext at character index {tamper_idx}.")
        attack_log.append("[ATTACKER] 📤 Forwarding tampered packet to the receiver...")
        
    except Exception as e:
        attack_log.append(f"[ATTACKER] ❌ Failed to tamper: {str(e)}")
        
    return {
        "tampered_packet": packet,
        "attack_log": attack_log
    }

if __name__ == "__main__":
    print("--- Tampering Attack Simulation ---")
    
    # Create a dummy packet
    demo_packet = SecurePacket.create_new("Banking", "Alice", "Bob")
    demo_packet.ciphertext = "aBcDeFg1234567890XYZ=="
    
    print(f"Original Ciphertext: {demo_packet.ciphertext}")
    
    # Run the attack simulation
    result = simulate_tampering(demo_packet)
    
    print("\n--- Attack Log ---")
    for log_entry in result["attack_log"]:
        print(log_entry)
        
    print(f"\nTampered Ciphertext: {result['tampered_packet'].ciphertext}")
