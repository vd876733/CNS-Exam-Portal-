import sys
import os
import copy
import json

# Ensure imports work for our project structure
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.packet import SecurePacket

def simulate_mitm_metadata_hijack(packet: SecurePacket) -> dict:
    """
    EDUCATIONAL MITM SIMULATION
    ---------------------------
    This module simulates a Man-in-the-Middle (MITM) intercepting a packet 
    and attempting to substitute communication metadata (e.g., changing the 
    'receiver' field to hijack a transaction).
    
    In network security, routing metadata is often visible. If an attacker 
    changes it, the receiving system's integrity checks (HMAC) and authenticity 
    checks (RSA Signatures) must fail, because the attacker cannot recalculate 
    the signatures without the private keys.
    """
    attack_log = [
        "--- EDUCATIONAL MITM SIMULATION ---",
        "🦹 [MITM] Intercepting packet during transit...",
        f"🦹 [MITM] Current Original Receiver: '{packet.receiver}'",
        "🦹 [MITM] Attempting to hijack transaction by modifying metadata..."
    ]
    
    # 1. Attacker clones the packet
    tampered_packet = copy.deepcopy(packet)
    
    # 2. Attacker modifies the metadata (e.g., trying to route money/data to themselves)
    tampered_packet.receiver = "Eve (Attacker)"
    attack_log.append(f"🦹 [MITM] Modified Receiver field to: '{tampered_packet.receiver}'")
    attack_log.append("🦹 [MITM] Forwarding tampered packet to the destination...")
    
    # 3. Receiver Verification Phase (The Defense)
    attack_log.append("\n🛡️ [RECEIVER] Processing incoming packet...")
    attack_log.append("🛡️ [RECEIVER] Re-calculating cryptographic hashes over received data...")
    
    # In a real system, the HMAC and RSA Signature are generated over a canonical 
    # string combining the ciphertext AND the metadata. 
    # Because the attacker changed 'Bob' to 'Eve', the new calculated hash 
    # will completely differ from the one the Sender originally signed.
    
    attack_log.append("\n🛡️ [DEFENSE 1: INTEGRITY]")
    attack_log.append("❌ HMAC-SHA256 VERIFICATION FAILED.")
    attack_log.append("   Reason: The data payload was altered in transit. The provided HMAC does not match.")
    
    attack_log.append("\n🛡️ [DEFENSE 2: AUTHENTICITY & NON-REPUDIATION]")
    attack_log.append("❌ RSA DIGITAL SIGNATURE VERIFICATION FAILED.")
    attack_log.append("   Reason: The attacker cannot generate a valid RSA signature for the new data without the Sender's Private Key.")
    
    attack_log.append("\n🚨 [SYSTEM RESULT] ACTION: Packet Dropped. Hijack Attempt Thwarted.")
    
    return {
        "tampered_packet": tampered_packet,
        "attack_log": attack_log,
        "attack_successful": False
    }

if __name__ == "__main__":
    print("--- Running MITM Test ---")
    demo_packet = SecurePacket.create_new("Banking", "Alice", "Bob")
    demo_packet.ciphertext = "secure_encrypted_data"
    demo_packet.authentication_tag = "valid_hmac_123"
    demo_packet.digital_signature = "valid_rsa_sig_456"
    
    result = simulate_mitm_metadata_hijack(demo_packet)
    
    for line in result["attack_log"]:
        print(line)
