from models.packet import SecurePacket
from security.authentication import authenticate_user
from security.replay_protection import validate_packet_freshness
from crypto.diffie_hellman import (
    generate_dh_parameters, generate_key_pair, 
    derive_shared_secret, derive_session_key, get_key_fingerprint
)
from crypto.hashing import hash_data
from crypto.rsa import generate_rsa_key_pair
from crypto.signatures import sign_data, verify_signature
from crypto.aes import encrypt_data, decrypt_data
from crypto.hmac_utils import generate_hmac, verify_hmac
from attacks.tampering import simulate_tampering
from attacks.replay import simulate_replay_attack
from attacks.mitm import simulate_mitm_metadata_hijack
from attacks.eavesdropping import simulate_eavesdropping

def run_secure_transmission(
    sender_id: str,
    sender_pwd: str,
    receiver_id: str,
    plaintext: str,
    scenario: str,
    attack_type: str = "None"
) -> list:
    """
    Generic secure transmission pipeline, applicable to both Examiner-to-Student
    (Question Papers) and Student-to-Examiner (Answer Submissions).
    
    WARNING: This is a simulation engine for educational purposes. 
    It is not guaranteed to be production-ready.
    """
    steps_log = []
    
    def log_step(name, status, explanation, algo=None, safe_meta=None):
        steps_log.append({
            "step_name": name,
            "status": status,
            "explanation": explanation,
            "algorithm": algo,
            "safe_metadata": safe_meta or {}
        })

    # 1. Authenticate Sender
    auth_result = authenticate_user(sender_id, sender_pwd)
    if not auth_result["success"]:
        log_step("Authenticate Sender", "FAILED", auth_result["message"])
        return steps_log
    log_step("Authenticate Sender", "SUCCESS", f"User '{sender_id}' authenticated successfully.")

    # 2. Key Establishment (Diffie-Hellman to AES-256 Session Key)
    dh_params = generate_dh_parameters()
    sender_dh_priv, sender_dh_pub = generate_key_pair(dh_params)
    receiver_dh_priv, receiver_dh_pub = generate_key_pair(dh_params)
    
    sender_shared_secret = derive_shared_secret(sender_dh_priv, receiver_dh_pub)
    receiver_shared_secret = derive_shared_secret(receiver_dh_priv, sender_dh_pub)
    
    sender_aes_key = derive_session_key(sender_shared_secret)
    receiver_aes_key = derive_session_key(receiver_shared_secret)
    
    log_step(
        "Establish Session Key", "SUCCESS", 
        "Secure session key derived via Diffie-Hellman and HKDF.",
        algo="DH + HKDF-SHA256",
        safe_meta={"key_fingerprint": get_key_fingerprint(sender_aes_key)}
    )

    # Setup RSA Keys for Sender (In a real system, these are pre-distributed PKI)
    sender_rsa_priv, sender_rsa_pub = generate_rsa_key_pair()

    # 3. Hash Data
    data_hash = hash_data(plaintext)
    log_step(
        "Compute Data Hash", "SUCCESS", 
        "Data integrity baseline computed.",
        algo="SHA-256",
        safe_meta={"hash_digest": data_hash}
    )

    # 4. Digital Signature
    digital_sig = sign_data(plaintext, sender_rsa_priv)
    log_step(
        "Digital Signature", "SUCCESS", 
        "Sender non-repudiation established.",
        algo="RSA-PSS"
    )

    # 5. Authenticated Encryption
    enc_payload = encrypt_data(plaintext, sender_aes_key)
    ciphertext_combined = f"{enc_payload['nonce_b64']}:{enc_payload['ciphertext_b64']}"
    log_step(
        "Encrypt Data", "SUCCESS", 
        "Data encrypted ensuring confidentiality and integrity (GCM).",
        algo="AES-256-GCM"
    )

    # 6. Build Secure Packet
    packet = SecurePacket.create_new(
        scenario=scenario, 
        sender=sender_id, 
        receiver=receiver_id, 
        algorithm="AES-256-GCM + RSA-PSS + HMAC-SHA256"
    )
    packet.ciphertext = ciphertext_combined
    packet.hash = data_hash
    packet.digital_signature = digital_sig
    
    # Adding HMAC over metadata AND ciphertext to complement GCM (Encrypt-then-MAC + Associated Data)
    authenticated_payload = f"{packet.sender}|{packet.receiver}|{packet.transaction_id}|{packet.timestamp}|{packet.nonce}|{packet.ciphertext}"
    mac = generate_hmac(authenticated_payload, sender_aes_key)
    packet.authentication_tag = mac
    
    # The SecurePacket natively only contains ciphertext, signatures, and routing metadata.
    # It NEVER contains private keys, passwords, or decrypted plaintext.
    safe_packet_meta = packet.to_dict()
    
    log_step(
        "Build Secure Packet", "SUCCESS", 
        "Packet constructed with metadata and payloads.",
        safe_meta=safe_packet_meta
    )

    # 7. Simulate Transmission & Attacks
    if attack_type == "None" or not attack_type:
        log_step("Simulate Transmission", "IN-TRANSIT", "Packet traveled without interference.")
    else:
        attack_title = f"Simulate Transmission ({attack_type})"
        if attack_type == "Eavesdropping":
            result = simulate_eavesdropping(packet)
            log_step(attack_title, "SIMULATED", "Passive interception.", safe_meta={"log": result["attack_log"]})
        elif attack_type == "Tampering (MITM)":
            result = simulate_tampering(packet)
            packet = result["tampered_packet"]
            log_step(attack_title, "SIMULATED", "Packet actively altered.", safe_meta={"log": result["attack_log"]})
        elif attack_type == "Metadata Hijack (MITM)":
            result = simulate_mitm_metadata_hijack(packet)
            packet = result["tampered_packet"]
            log_step(attack_title, "SIMULATED", "Metadata hijacked.", safe_meta={"log": result["attack_log"]})
        elif attack_type == "Replay Attack":
            result = simulate_replay_attack(packet, delay_seconds=1)
            packet = result["replayed_packet"] 
            log_step(attack_title, "SIMULATED", "Packet replayed.", safe_meta={"log": result["ui_flow"]})

    # 8. Replay Protection
    freshness = validate_packet_freshness(packet.transaction_id, packet.nonce, packet.timestamp)
    if freshness["status"] == "REPLAY ATTACK DETECTED":
        log_step("Replay Protection", "FAILED", freshness["reason"])
        return steps_log
    log_step("Replay Protection", "SUCCESS", "Packet is fresh (valid nonce/timestamp).")

    # 9. Verify Outer HMAC (over metadata + ciphertext)
    authenticated_payload = f"{packet.sender}|{packet.receiver}|{packet.transaction_id}|{packet.timestamp}|{packet.nonce}|{packet.ciphertext}"
    is_valid_hmac = verify_hmac(authenticated_payload, receiver_aes_key, packet.authentication_tag)
    if not is_valid_hmac:
        log_step("Verify HMAC", "FAILED", "HMAC mismatch. Payload tampered in transit.")
        return steps_log
    log_step("Verify HMAC", "SUCCESS", "Outer integrity intact.")

    # 10. Authenticated Decryption (AES-GCM)
    decrypted_data = None
    try:
        aes_nonce_b64, actual_ciphertext_b64 = packet.ciphertext.split(":")
        decrypted_data = decrypt_data(actual_ciphertext_b64, receiver_aes_key, aes_nonce_b64)
        log_step("Authenticated Decryption", "SUCCESS", "Data successfully decrypted and verified (GCM).", algo="AES-256-GCM")
    except Exception as e:
        log_step("Authenticated Decryption", "FAILED", f"Decryption/GCM Auth failed: {str(e)}")
        return steps_log

    # 11. Verify Digital Signature
    is_valid_sig = verify_signature(decrypted_data, packet.digital_signature, sender_rsa_pub)
    if not is_valid_sig:
        log_step("Verify Digital Signature", "FAILED", "Signature mismatch. Authenticity cannot be proven.")
        return steps_log
    log_step("Verify Digital Signature", "SUCCESS", "Signature verified against recovered plaintext.", algo="RSA-PSS")

    # 12. Final Validation & Data Release
    computed_hash = hash_data(decrypted_data)
    if computed_hash != packet.hash:
        log_step("Release Data", "FAILED", "Final hash mismatch. Rejecting plaintext.")
        return steps_log
        
    log_step("Release Data", "SUCCESS", "All security checks passed. Plaintext released safely.", safe_meta={"recovered_plaintext": decrypted_data})

    return steps_log

def transmit_question_paper(examiner_id: str, examiner_pwd: str, student_id: str, paper_content: str, attack_type: str = "None") -> list:
    """
    Orchestrates the transmission of a confidential question paper from an Examiner to a Student.
    """
    return run_secure_transmission(
        sender_id=examiner_id,
        sender_pwd=examiner_pwd,
        receiver_id=student_id,
        plaintext=paper_content,
        scenario="SecureExam - Question Paper Transmission",
        attack_type=attack_type
    )

def submit_student_answer(student_id: str, student_pwd: str, examiner_id: str, answer_content: str, attack_type: str = "None") -> list:
    """
    Orchestrates the secure submission of an exam answer from a Student to an Examiner.
    """
    return run_secure_transmission(
        sender_id=student_id,
        sender_pwd=student_pwd,
        receiver_id=examiner_id,
        plaintext=answer_content,
        scenario="SecureExam - Answer Submission",
        attack_type=attack_type
    )
