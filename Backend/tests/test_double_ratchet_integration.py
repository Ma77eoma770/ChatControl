import sys
import os
import unittest
import base64
import json
import sqlite3

# Add Backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.double_ratchet import DoubleRatchetSession
from services.crypto_service import (
    genera_chiavi, derive_shared_secret, cifra_payload_dr, decifra_payload,
    cifra_vault, decifra_vault
)
from database.sqlite import initDB, get_connection

class TestDoubleRatchetIntegration(unittest.TestCase):

    def setUp(self):
        # Initialise in-memory DB or test database file if needed
        initDB()

    def test_full_dr_messaging_exchange(self):
        # 1. Generate keypairs for Alice and Bob
        alice_pub, alice_priv = genera_chiavi()
        bob_pub, bob_priv = genera_chiavi()

        self.assertIsNotNone(alice_pub)
        self.assertIsNotNone(bob_pub)

        # 2. Derive shared secrets
        shared_secret_alice = derive_shared_secret(alice_priv, bob_pub)
        shared_secret_bob = derive_shared_secret(bob_priv, alice_pub)
        self.assertEqual(shared_secret_alice, shared_secret_bob)

        # 3. Instantiate sessions (Alice = Initiator, Bob = Responder)
        alice_session = DoubleRatchetSession.init_alice(shared_secret_alice, bob_pub)
        bob_session = DoubleRatchetSession.init_bob(shared_secret_bob, bob_priv)

        # --- Message 1: Alice -> Bob ---
        msg1_str = json.dumps({"cif": "on", "text": "Ciao Bob! Primo messaggio Double Ratchet", "id": "msg_001"})
        enc1_b64 = cifra_payload_dr(msg1_str, alice_session)

        # Decode raw envelope JSON
        raw_env1 = json.loads(base64.b64decode(enc1_b64).decode('utf-8'))
        self.assertEqual(raw_env1.get("v"), "dr_v1")
        self.assertEqual(raw_env1["header"]["n"], 0)
        self.assertEqual(raw_env1["header"]["pn"], 0)

        # Bob decrypts Message 1
        dec1_bytes = decifra_payload(enc1_b64, [bob_priv], dr_session=bob_session)
        self.assertIsNotNone(dec1_bytes)
        dec1_dict = json.loads(dec1_bytes.decode('utf-8'))
        self.assertEqual(dec1_dict["text"], "Ciao Bob! Primo messaggio Double Ratchet")

        # --- Message 2: Bob -> Alice (Triggers DH Ratchet on Bob's side) ---
        msg2_str = json.dumps({"cif": "on", "text": "Ciao Alice! Il DH Ratchet ha appena avanzato la chiave.", "id": "msg_002"})
        enc2_b64 = cifra_payload_dr(msg2_str, bob_session)

        raw_env2 = json.loads(base64.b64decode(enc2_b64).decode('utf-8'))
        self.assertEqual(raw_env2.get("v"), "dr_v1")

        # Alice decrypts Message 2 (Triggers DH Ratchet on Alice's side)
        dec2_bytes = decifra_payload(enc2_b64, [alice_priv], dr_session=alice_session)
        self.assertIsNotNone(dec2_bytes)
        dec2_dict = json.loads(dec2_bytes.decode('utf-8'))
        self.assertEqual(dec2_dict["text"], "Ciao Alice! Il DH Ratchet ha appena avanzato la chiave.")

        # --- Message 3 & 4: Alice -> Bob (Multiple symmetric ratchet steps) ---
        enc3_b64 = cifra_payload_dr(json.dumps({"cif": "on", "text": "Messaggio 3 di Alice", "id": "msg_003"}), alice_session)
        enc4_b64 = cifra_payload_dr(json.dumps({"cif": "on", "text": "Messaggio 4 di Alice", "id": "msg_004"}), alice_session)

        dec3_bytes = decifra_payload(enc3_b64, [bob_priv], dr_session=bob_session)
        dec4_bytes = decifra_payload(enc4_b64, [bob_priv], dr_session=bob_session)

        self.assertEqual(json.loads(dec3_bytes.decode('utf-8'))["text"], "Messaggio 3 di Alice")
        self.assertEqual(json.loads(dec4_bytes.decode('utf-8'))["text"], "Messaggio 4 di Alice")

    def test_dr_session_serialization_and_vault(self):
        alice_pub, alice_priv = genera_chiavi()
        bob_pub, bob_priv = genera_chiavi()

        shared_secret = derive_shared_secret(alice_priv, bob_pub)
        alice_session = DoubleRatchetSession.init_alice(shared_secret, bob_pub)

        # Perform 2 encryptions
        cifra_payload_dr("Msg 1", alice_session)
        cifra_payload_dr("Msg 2", alice_session)

        session_dict = alice_session.to_dict()
        masterkey = base64.urlsafe_b64encode(os.urandom(32))

        # Encrypt vault blob
        encrypted_vault = cifra_vault({"dr_session": session_dict}, masterkey)

        # Decrypt vault blob
        restored_vault = decifra_vault(encrypted_vault, masterkey)
        restored_session = DoubleRatchetSession.from_dict(restored_vault["dr_session"])

        self.assertEqual(restored_session.ns, alice_session.ns)
        self.assertEqual(restored_session.pn, alice_session.pn)

        # Encrypt with restored session
        enc3_b64 = cifra_payload_dr("Msg 3 da sessione ripristinata", restored_session)

        bob_session = DoubleRatchetSession.init_bob(shared_secret, bob_priv)
        # Bob decrypts Msg 1, 2, 3
        # Since Msg 1 & 2 were done by original session, restored session has ns=2
        raw_env3 = json.loads(base64.b64decode(enc3_b64).decode('utf-8'))
        self.assertEqual(raw_env3["header"]["n"], 2)

        dec3 = bob_session.decrypt(raw_env3)
        self.assertEqual(dec3.decode('utf-8'), "Msg 3 da sessione ripristinata")

    def test_uninitialized_bob_encrypt_graceful_handling(self):
        bob_pub, bob_priv = genera_chiavi()
        bob_session = DoubleRatchetSession.init_bob(b"0" * 32, bob_priv)
        self.assertIsNone(bob_session.cks)
        # Should return None gracefully instead of raising unhandled ValueError
        res = cifra_payload_dr("Test message", bob_session)
        self.assertIsNone(res)

if __name__ == '__main__':
    unittest.main()

