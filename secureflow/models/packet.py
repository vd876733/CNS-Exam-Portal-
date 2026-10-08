import json
import time
import uuid
import secrets
from dataclasses import dataclass, asdict

@dataclass
class SecurePacket:
    """
    Represents the data structure transmitted over the untrusted network.
    
    CRITICAL SECURITY RULE: 
    This packet MUST NEVER contain plaintext data or private keys. 
    It only contains necessary routing metadata and cryptographically protected material.
    """
    # 1. Routing & Metadata
    transaction_id: str
    timestamp: float
    nonce: str
    scenario: str
    sender: str
    receiver: str
    algorithm: str
    
    # 2. Cryptographic Payloads (Stored as Base64/Hex strings for safe transport & UI display)
    ciphertext: str = ""
    authentication_tag: str = "" # e.g., the HMAC-SHA256 signature
    hash: str = ""               # SHA-256 hash of the original plaintext
    digital_signature: str = ""  # RSA-PSS signature
    
    @classmethod
    def create_new(cls, scenario: str, sender: str, receiver: str, algorithm: str = "AES-256-GCM + RSA-2048"):
        """
        Factory method to create a new SecurePacket with fresh anti-replay metadata.
        
        Args:
            scenario (str): Context of the data (e.g., 'Banking', 'Healthcare').
            sender (str): The entity sending the packet.
            receiver (str): The intended recipient.
            algorithm (str): Label indicating algorithms used.
        """
        return cls(
            transaction_id=str(uuid.uuid4()), # Globally unique identifier
            timestamp=time.time(),            # Unix timestamp for freshness validation
            nonce=secrets.token_hex(16),      # Secure random 32-character hex string (Number Used Once)
            scenario=scenario,
            sender=sender,
            receiver=receiver,
            algorithm=algorithm
        )

    def to_dict(self) -> dict:
        """
        Returns the packet as a dictionary. 
        Highly useful for Streamlit's st.json() or st.dataframe() visualizations.
        """
        return asdict(self)
        
    def to_json(self) -> str:
        """
        Serializes the packet to a JSON string for transmission over the simulated network.
        """
        return json.dumps(self.to_dict(), indent=4)

    @classmethod
    def from_json(cls, json_str: str) -> 'SecurePacket':
        """
        Deserializes a JSON string back into a SecurePacket object.
        """
        data = json.loads(json_str)
        return cls(**data)

# Unit-test example demonstrating the flow
if __name__ == "__main__":
    print("--- SecurePacket Model Demonstration ---")
    
    # 1. Create a fresh packet (Pre-encryption phase)
    print("\n[!] Initializing new packet...")
    packet = SecurePacket.create_new(
        scenario="Banking",
        sender="Alice",
        receiver="Bob"
    )
    
    # 2. Simulate the cryptographic pipeline populating the packet
    # (In reality, this is done by the crypto/ modules)
    packet.ciphertext = "aBcDeFg12345=="
    packet.authentication_tag = "9f86d081884c7d659a2feaa0c55ad015"
    packet.hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    packet.digital_signature = "SigXyZ123=="
    
    # 3. Serialize for network transit
    print("\n[!] Serializing packet for network transit...")
    json_payload = packet.to_json()
    print(json_payload)
    
    # 4. Deserialize on receiver end
    print("\n[!] Deserializing packet on Receiver end...")
    received_packet = SecurePacket.from_json(json_payload)
    print(f"[+] Reconstructed Packet ID: {received_packet.transaction_id}")
    print(f"[+] Timestamp for Replay Check: {received_packet.timestamp}")
    print(f"[+] Nonce for Replay Check: {received_packet.nonce}")
