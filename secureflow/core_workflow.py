import time

# Import Models and Security
from models.packet import SecurePacket
from security.authentication import authenticate_user
from security.replay_protection import validate_packet_freshness

# Import Crypto Modules
from crypto.diffie_hellman import (
    generate_dh_parameters, generate_key_pair, 
    derive_shared_secret, derive_session_key, get_key_fingerprint
)
from crypto.hashing import hash_data
from crypto.rsa import generate_rsa_key_pair
from crypto.signatures import sign_data, verify_signature
from crypto.aes import encrypt_data, decrypt_data
from crypto.hmac_utils import generate_hmac, verify_hmac

# Import Attack Simulators
from attacks.tampering import simulate_tampering
from attacks.replay import simulate_replay_attack
from attacks.mitm import simulate_mitm_metadata_hijack
from attacks.eavesdropping import simulate_eavesdropping

def execute_security_workflow(
    sender_username: str,
    sender_password: str,
    receiver_name: str,
    plaintext_data: str,
    scenario: str,
    attack_type: str = "None"
) -> list:
    """
    Executes the entire SecureFlow cryptographic pipeline from end to end.
    
    This acts as the central brain of the application. It runs the logic entirely 
    independent of any UI code. It returns a structured list of dictionaries that 
    the Streamlit frontend can easily iterate over and display.
    """
    steps_log = []
    
    def log_step(title, status, details=None, is_error=False, payload=None):
        steps_log.append({
            "title": title,
            "status": status,
            "details": details or "",
            "is_error": is_error,
            "payload": payload
        })

    # 1. Authenticate sender
    auth_result = authenticate_user(sender_username, sender_password)
    if not auth_result["success"]:
        log_step("1. Authenticate sender", "FAILED", auth_result["message"], is_error=True)
        return steps_log
    log_step("1. Authenticate sender", "SUCCESS", f"User '{sender_username}' authenticated successfully.")

    # 2. Generate Diffie-Hellman key pairs
    dh_params = generate_dh_parameters()
    sender_dh_priv, sender_dh_pub = generate_key_pair(dh_params)
    receiver_dh_priv, receiver_dh_pub = generate_key_pair(dh_params)
    log_step("2. Generate Diffie-Hellman key pairs", "SUCCESS", "DH parameters and key pairs generated for sender and receiver.")

    # 3. Establish shared secret
    sender_shared_secret = derive_shared_secret(sender_dh_priv, receiver_dh_pub)
    receiver_shared_secret = derive_shared_secret(receiver_dh_priv, sender_dh_pub)
    log_step("3. Establish shared secret", "SUCCESS", "Shared secrets established successfully between sender and receiver.")
    
    # 4. Derive AES session key using HKDF-SHA256
    sender_aes_key = derive_session_key(sender_shared_secret)
    receiver_aes_key = derive_session_key(receiver_shared_secret)
    log_step("4. Derive AES session key using HKDF-SHA256", "SUCCESS", f"Derived AES-256 session key (Fingerprint: {get_key_fingerprint(sender_aes_key)}).")

    # (Generate RSA keys for signatures - silently or just as setup)
    sender_rsa_priv, sender_rsa_pub = generate_rsa_key_pair()

    # 5. Create SHA-256 hash of the original data
    data_hash = hash_data(plaintext_data)
    log_step("5. Create SHA-256 hash of the original data", "SUCCESS", f"Plaintext hashed. Digest: {data_hash}")

    # 6. Create RSA digital signature
    digital_sig = sign_data(plaintext_data, sender_rsa_priv)
    log_step("6. Create RSA digital signature", "SUCCESS", "Sender signed the plaintext data using their RSA Private Key.")

    # 7. Encrypt the data using AES-256-GCM
    enc_payload = encrypt_data(plaintext_data, sender_aes_key)
    ciphertext_combined = f"{enc_payload['nonce_b64']}:{enc_payload['ciphertext_b64']}"
    log_step("7. Encrypt the data using AES-256-GCM", "SUCCESS", "Plaintext encrypted. Confidentiality established.")

    # 8. Generate HMAC-SHA256 over the appropriate transmitted representation
    mac = generate_hmac(ciphertext_combined, sender_aes_key)
    log_step("8. Generate HMAC-SHA256 over the appropriate transmitted representation", "SUCCESS", "Encrypt-then-MAC pattern applied on the ciphertext.")

    # 9. Create SecurePacket
    packet = SecurePacket.create_new(scenario, sender_username, receiver_name, algorithm="AES-256-GCM + RSA-PSS + HMAC-SHA256")
    packet.ciphertext = ciphertext_combined
    packet.hash = data_hash
    packet.digital_signature = digital_sig
    packet.authentication_tag = mac
    log_step("9. Create SecurePacket", "SUCCESS", "Packet constructed and ready for transit.", payload=packet.to_dict())

    # 10. Simulate transmission through an untrusted network
    log_step("10. Simulate transmission through an untrusted network", "IN-TRANSIT", "Packet entering untrusted network.")
    
    # 11. Optionally apply an attack
    if attack_type == "None" or not attack_type:
        log_step("11. Optionally apply an attack", "SKIPPED", "No attack simulated. Packet traveling safely.")
    else:
        attack_title = "11. Optionally apply an attack"
        if attack_type == "Eavesdropping":
            result = simulate_eavesdropping(packet)
            log_step(attack_title, "SIMULATED", "\n".join(result["attack_log"]))
        elif attack_type == "Tampering (MITM)":
            result = simulate_tampering(packet)
            packet = result["tampered_packet"]
            log_step(attack_title, "SIMULATED", "\n".join(result["attack_log"]))
        elif attack_type == "Metadata Hijack (MITM)":
            result = simulate_mitm_metadata_hijack(packet)
            packet = result["tampered_packet"]
            log_step(attack_title, "SIMULATED", "\n".join(result["attack_log"]))
        elif attack_type == "Replay Attack":
            result = simulate_replay_attack(packet, delay_seconds=1)
            packet = result["replayed_packet"] 
            log_step(attack_title, "SIMULATED", "\n".join(result["ui_flow"]))

    # 12. Verify replay protection
    freshness = validate_packet_freshness(packet.transaction_id, packet.nonce, packet.timestamp)
    if freshness["status"] == "REPLAY ATTACK DETECTED":
        log_step("12. Verify replay protection", "FAILED", freshness["reason"], is_error=True)
        return steps_log
    log_step("12. Verify replay protection", "SUCCESS", "Packet is fresh. No replay attack detected.")

    # 13. Verify HMAC
    is_valid_hmac = verify_hmac(packet.ciphertext, receiver_aes_key, packet.authentication_tag)
    if not is_valid_hmac:
        log_step("13. Verify HMAC", "FAILED", "Integrity compromise detected. Ciphertext altered in transit.", is_error=True)
        return steps_log
    log_step("13. Verify HMAC", "SUCCESS", "Data integrity confirmed.")

    # Decrypt AES ciphertext (Need to do this to verify the signature on plaintext)
    decrypted_data = None
    decryption_error = None
    try:
        aes_nonce_b64, actual_ciphertext_b64 = packet.ciphertext.split(":")
        decrypted_data = decrypt_data(actual_ciphertext_b64, receiver_aes_key, aes_nonce_b64)
    except Exception as e:
        decryption_error = e

    # 14. Verify digital signature
    if decryption_error:
        log_step("14. Verify digital signature", "FAILED", "Cannot verify signature due to decryption failure.", is_error=True)
        return steps_log
    else:
        is_valid_sig = verify_signature(decrypted_data, packet.digital_signature, sender_rsa_pub)
        if not is_valid_sig:
            log_step("14. Verify digital signature", "FAILED", "Authenticity compromise detected.", is_error=True)
            return steps_log
        log_step("14. Verify digital signature", "SUCCESS", "Authenticity and Non-repudiation confirmed. Sender verified.")

    # 15. Decrypt AES ciphertext
    if decryption_error:
        log_step("15. Decrypt AES ciphertext", "FAILED", f"Error: {decryption_error}", is_error=True)
        return steps_log
    else:
        log_step("15. Decrypt AES ciphertext", "SUCCESS", "Ciphertext successfully decrypted using AES session key.")

    # 16. Display the recovered plaintext
    log_step("16. Display the recovered plaintext", "SUCCESS", f"Recovered Data: '{decrypted_data}'", payload={"recovered_plaintext": decrypted_data})

    # 17. Generate final security status
    log_step("17. Generate final security status", "SECURE", "Workflow completed successfully. Data is secure.")

    return steps_log
