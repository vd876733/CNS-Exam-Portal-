import sys
import os

# Ensure the parent directory is in the path so we can import the models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.packet import SecurePacket

def simulate_eavesdropping(packet: SecurePacket) -> dict:
    """
    EDUCATIONAL EAVESDROPPING SIMULATION
    ------------------------------------
    This module simulates a passive eavesdropping attack (network sniffing).
    
    It demonstrates that while an attacker on a public network (like public Wi-Fi) 
    can intercept the packet and view its routing metadata, they CANNOT read the 
    actual application data or extract the secret keys.
    
    This visually proves the concept of CONFIDENTIALITY provided by AES-256 encryption.
    """
    attack_log = [
        "--- PASSIVE EAVESDROPPING (SNIFFING) SIMULATION ---",
        "🦹 [EAVESDROPPER] Packet intercepted via network sniffer (e.g., Wireshark).",
        "🦹 [EAVESDROPPER] Inspecting packet contents..."
    ]
    
    # What the attacker CAN see (Metadata, Ciphertext, and Hashes)
    # They can see the ciphertext, but it looks like absolute gibberish.
    visible_data = {
        "transaction_id": packet.transaction_id,
        "timestamp": packet.timestamp,
        "sender": packet.sender,
        "receiver": packet.receiver,
        "nonce": packet.nonce,
        "algorithm": packet.algorithm,
        "ciphertext": packet.ciphertext,
        "authentication_tag (HMAC)": packet.authentication_tag,
        "digital_signature (RSA)": packet.digital_signature
    }
    
    attack_log.append("\n[WHAT THE ATTACKER SEES]")
    for key, value in visible_data.items():
        # Truncating long strings for display purposes in the log
        display_val = str(value)[:30] + "..." if len(str(value)) > 30 else value
        attack_log.append(f"  - {key}: {display_val}")
        
    attack_log.append("\n[SECURITY ANALYSIS: WHY THIS IS SAFE]")
    attack_log.append("🛡️ CONFIDENTIALITY PROTECTED: Because of AES-256, the plaintext is completely unreadable.")
    attack_log.append("🛡️ KEYS PROTECTED: No secret keys (AES Session Keys or RSA Private Keys) are present in the packet.")
    attack_log.append("🚨 CONCLUSION: Attacker cannot decipher the data. Eavesdropping yields no sensitive information.")
    
    return {
        "sniffed_data": visible_data,
        "attack_log": attack_log
    }

if __name__ == "__main__":
    print("--- Eavesdropping Test ---")
    demo_packet = SecurePacket.create_new("Healthcare", "Doctor A", "Server")
    demo_packet.ciphertext = "5c8b93b4a2d3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9=="
    demo_packet.authentication_tag = "9f86d081884c7d659a2feaa0c55ad015"
    demo_packet.digital_signature = "SigXyZ123..."
    
    result = simulate_eavesdropping(demo_packet)
    
    for line in result["attack_log"]:
        print(line)
