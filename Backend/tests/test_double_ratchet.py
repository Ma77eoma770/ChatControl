import sys
import os
import unittest
import base64

# Add services to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.double_ratchet import DoubleRatchetSession
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

class TestDoubleRatchet(unittest.TestCase):

    def test_double_ratchet_basic_flow(self):
        # Shared secret standard (32 byte)
        shared_secret = os.urandom(32)

        # Bob genera una propria chiave DH statica (Bob DH public key)
        bob_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        bob_priv_b64 = base64.b64encode(bob_priv.private_bytes_raw()).decode('utf-8')
        bob_pub_b64 = base64.b64encode(bob_priv.public_key().public_bytes_raw()).decode('utf-8')

        # Alice ed Bob inizializzano le sessioni
        alice_session = DoubleRatchetSession.init_alice(shared_secret, bob_pub_b64)
        bob_session = DoubleRatchetSession.init_bob(shared_secret, bob_priv_b64)

        # 1. Alice -> Bob (Messaggio 1)
        msg1_plaintext = "Ciao Bob, questo è il primo messaggio Double Ratchet!"
        enc1 = alice_session.encrypt(msg1_plaintext)

        dec1 = bob_session.decrypt(enc1).decode('utf-8')
        self.assertEqual(dec1, msg1_plaintext)

        # 2. Bob -> Alice (Messaggio 2 - Innesca DH Ratchet)
        msg2_plaintext = "Ciao Alice! Il DH Ratchet ha appena avanzato la chiave."
        enc2 = bob_session.encrypt(msg2_plaintext)

        dec2 = alice_session.decrypt(enc2).decode('utf-8')
        self.assertEqual(dec2, msg2_plaintext)

        # 3. Alice -> Bob (Messaggio 3 - Innesca ulteriore DH Ratchet)
        msg3_plaintext = "Perfetto! Abbiamo la Break-in Recovery e la Perfect Forward Secrecy."
        enc3 = alice_session.encrypt(msg3_plaintext)

        dec3 = bob_session.decrypt(enc3).decode('utf-8')
        self.assertEqual(dec3, msg3_plaintext)

    def test_skipped_messages(self):
        shared_secret = os.urandom(32)
        bob_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        bob_priv_b64 = base64.b64encode(bob_priv.private_bytes_raw()).decode('utf-8')
        bob_pub_b64 = base64.b64encode(bob_priv.public_key().public_bytes_raw()).decode('utf-8')

        alice_session = DoubleRatchetSession.init_alice(shared_secret, bob_pub_b64)
        bob_session = DoubleRatchetSession.init_bob(shared_secret, bob_priv_b64)

        # Alice invia 3 messaggi di fila
        enc1 = alice_session.encrypt("Messaggio 1")
        enc2 = alice_session.encrypt("Messaggio 2")
        enc3 = alice_session.encrypt("Messaggio 3")

        # Bob li riceve fuori ordine: prima il 3, poi il 1, poi il 2
        dec3 = bob_session.decrypt(enc3).decode('utf-8')
        self.assertEqual(dec3, "Messaggio 3")

        dec1 = bob_session.decrypt(enc1).decode('utf-8')
        self.assertEqual(dec1, "Messaggio 1")

        dec2 = bob_session.decrypt(enc2).decode('utf-8')
        self.assertEqual(dec2, "Messaggio 2")

    def test_serialization(self):
        shared_secret = os.urandom(32)
        bob_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        bob_priv_b64 = base64.b64encode(bob_priv.private_bytes_raw()).decode('utf-8')
        bob_pub_b64 = base64.b64encode(bob_priv.public_key().public_bytes_raw()).decode('utf-8')

        alice_session = DoubleRatchetSession.init_alice(shared_secret, bob_pub_b64)
        enc1 = alice_session.encrypt("Test serializzazione")

        # Serializza ed esegui il restore
        session_dict = alice_session.to_dict()
        restored_session = DoubleRatchetSession.from_dict(session_dict)

        enc2 = restored_session.encrypt("Messaggio da sessione ripristinata")

        bob_session = DoubleRatchetSession.init_bob(shared_secret, bob_priv_b64)
        dec1 = bob_session.decrypt(enc1).decode('utf-8')
        dec2 = bob_session.decrypt(enc2).decode('utf-8')

        self.assertEqual(dec1, "Test serializzazione")
        self.assertEqual(dec2, "Messaggio da sessione ripristinata")

if __name__ == '__main__':
    unittest.main()
