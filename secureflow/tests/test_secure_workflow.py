import unittest
import time
import uuid

from security.workflow import run_secure_transmission, transmit_question_paper, submit_student_answer
from security.authentication import DUMMY_DATABASE, _hash_password
from security.rate_limiter import check_rate_limit, reset_rate_limits
from security.replay_protection import clear_cache as clear_replay_cache
from models.packet import SecurePacket
import crypto.rsa as rsa_mod
import crypto.aes as aes_mod
import crypto.hashing as hash_mod
import crypto.hmac_utils as hmac_mod
from attacks.mitm import simulate_mitm_metadata_hijack
from unittest.mock import patch

class TestSecureWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Register a valid user for tests
        slt, hsh = _hash_password("password123")
        DUMMY_DATABASE["Valid_Examiner"] = {"salt": slt, "hash": hsh}
        DUMMY_DATABASE["Valid_Student"] = {"salt": slt, "hash": hsh}
        
        # Pre-generate DH params and RSA keys ONCE to speed up tests significantly
        from crypto.diffie_hellman import generate_dh_parameters, generate_key_pair
        from crypto.rsa import generate_rsa_key_pair
        cls.cached_dh_params = generate_dh_parameters()
        cls.cached_dh_keys = generate_key_pair(cls.cached_dh_params)
        cls.cached_rsa_keys = generate_rsa_key_pair()
        
        cls.patcher_dh = patch('security.workflow.generate_dh_parameters', return_value=cls.cached_dh_params)
        cls.patcher_dh_keys = patch('security.workflow.generate_key_pair', return_value=cls.cached_dh_keys)
        cls.patcher_dh_derive = patch('security.workflow.derive_shared_secret', return_value=b'test_shared_secret_1234567890123')
        cls.patcher_rsa = patch('security.workflow.generate_rsa_key_pair', return_value=cls.cached_rsa_keys)
        
        cls.patcher_dh.start()
        cls.patcher_dh_keys.start()
        cls.patcher_dh_derive.start()
        cls.patcher_rsa.start()

    @classmethod
    def tearDownClass(cls):
        cls.patcher_dh.stop()
        cls.patcher_dh_keys.stop()
        cls.patcher_dh_derive.stop()
        cls.patcher_rsa.stop()

    def setUp(self):
        # Reset caches before each test
        reset_rate_limits()
        clear_replay_cache()

    def get_failed_step(self, results):
        return next((s.get("step_name") for s in results if s.get("status") == "FAILED"), None)

    def test_1_valid_transmission_and_reception(self):
        # Test Case 1: Valid question-paper transmission and reception
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1: Test", attack_type="None")
        self.assertIsNone(self.get_failed_step(results), "Valid transmission should not fail any step")
        self.assertEqual(results[-1]["step_name"], "Release Data")

    def test_2_valid_student_submission(self):
        # Test Case 2: Valid student answer submission
        results = submit_student_answer("Valid_Student", "password123", "Valid_Examiner", "A1: Test", attack_type="None")
        self.assertIsNone(self.get_failed_step(results))
        self.assertEqual(results[-1]["step_name"], "Release Data")

    def test_3_wrong_user_authentication(self):
        # Test Case 3: Wrong user authentication
        results = transmit_question_paper("Valid_Examiner", "wrongpass", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Authenticate Sender")

    def test_4_ciphertext_tampering(self):
        # Test Case 4: Ciphertext tampering
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Tampering (MITM)")
        # Tampering alters the ciphertext, so HMAC verification should fail
        self.assertEqual(self.get_failed_step(results), "Verify HMAC")

    @patch('security.workflow.verify_hmac')
    def test_5_authentication_tag_tampering(self, mock_verify):
        # Test Case 5: Authentication-tag tampering
        # Instead of directly tampering mid-flight, we mock verify_hmac to fail
        mock_verify.return_value = False
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Verify HMAC")

    @patch('security.workflow.verify_signature')
    def test_6_digital_signature_failure(self, mock_verify):
        # Test Case 6: Digital-signature verification failure
        mock_verify.return_value = False
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Verify Digital Signature")

    def test_7_altered_metadata(self):
        # Test Case 7: Altered sender or recipient metadata
        # Currently, Metadata Hijack is designed to fail if HMAC includes metadata.
        # Let's see what happens with current implementation.
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Metadata Hijack (MITM)")
        
        # If it doesn't fail, we need to fix it!
        # According to standard AEAD / SecurePacket logic, metadata must be authenticated.
        failed_step = self.get_failed_step(results)
        self.assertIsNotNone(failed_step, "Metadata alteration MUST be caught by integrity checks")

    def test_8_replay_attack(self):
        # Test Case 8: Replay of an already accepted packet
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Replay Attack")
        self.assertEqual(self.get_failed_step(results), "Replay Protection")

    @patch('security.workflow.validate_packet_freshness')
    def test_9_stale_packet_rejection(self, mock_freshness):
        # Test Case 9: Stale packet rejection
        mock_freshness.return_value = {"status": "REPLAY ATTACK DETECTED", "reason": "Timestamp too old."}
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Replay Protection")

    @patch('security.workflow.decrypt_data')
    def test_10_invalid_packet_structure(self, mock_decrypt):
        # Test Case 10: Invalid packet structure leading to decryption failure or format error
        mock_decrypt.side_effect = Exception("Invalid format")
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Authenticated Decryption")

    def test_11_rate_limit_enforcement(self):
        # Test Case 11: Rate-limit enforcement
        reset_rate_limits()
        for i in range(10):
            check_rate_limit("Spammer", max_requests=10, window_seconds=10)
        rl = check_rate_limit("Spammer", max_requests=10, window_seconds=10)
        self.assertEqual(rl["status"], "rate limit exceeded")

    def test_12_key_establishment_failure(self):
        # Test Case 12: Failure during key establishment
        with patch('security.workflow.derive_shared_secret', side_effect=Exception("Invalid public key")):
            with self.assertRaises(Exception):
                transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")

    @patch('security.workflow.decrypt_data')
    def test_13_decryption_failure(self, mock_decrypt):
        # Test Case 13: Decryption failure
        mock_decrypt.side_effect = Exception("MAC check failed")
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        self.assertEqual(self.get_failed_step(results), "Authenticated Decryption")

    def test_14_no_plaintext_before_validation(self):
        # Test Case 14: Ensuring no plaintext is released before validation
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Tampering (MITM)")
        # Since tampering fails at HMAC, there should be no recovered_plaintext in any safe_metadata
        for step in results:
            self.assertNotIn("recovered_plaintext", step.get("safe_metadata", {}))

    def test_15_no_private_keys_in_logs(self):
        # Test Case 15: Ensuring private and session keys are not included in packet output or logs
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="None")
        for step in results:
            meta_str = str(step.get("safe_metadata", {})).lower()
            # It shouldn't contain private key data
            self.assertNotIn("private", meta_str)
            self.assertNotIn("secret", meta_str)
            # 'key_fingerprint' is fine, but raw keys are not
            self.assertFalse(any(k for k in step.get("safe_metadata", {}).keys() if "private" in k.lower() or "secret" in k.lower()))

    def test_16_failed_transmission_no_receipt(self):
        # Test Case 16: Ensuring failed transmissions do not produce accepted receipts
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Tampering (MITM)")
        self.assertNotEqual(results[-1]["step_name"], "Release Data")
        
    def test_17_eavesdropping_success(self):
        # Additional: Eavesdropping shouldn't fail pipeline, but should not reveal plaintext to attacker
        results = transmit_question_paper("Valid_Examiner", "password123", "Valid_Student", "Q1", attack_type="Eavesdropping")
        self.assertIsNone(self.get_failed_step(results))

if __name__ == '__main__':
    unittest.main()
