import sys
import os
import unittest
import base64
import json

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.dpi_service import (
    pad_payload_to_bucket, unpad_payload_from_bucket,
    apply_covert_mimicry, revert_covert_mimicry,
    create_decoy_payload
)
from services.crypto_service import genera_chiavi, cifra_payload, decifra_payload


class TestDPIService(unittest.TestCase):

    def test_pad_and_unpad_buckets(self):
        # 1. Payload breve (<256 byte) -> deve essere padrato a 256 byte
        short_data = b"Hello Anti-DPI World!"
        padded_short = pad_payload_to_bucket(short_data, buckets=[256, 1024, 4096])
        self.assertEqual(len(padded_short), 256)

        unpadded_short = unpad_payload_from_bucket(padded_short)
        self.assertEqual(unpadded_short, short_data)

        # 2. Payload medio (>256 byte, <1024 byte) -> deve essere padrato a 1024 byte
        medium_data = b"A" * 300
        padded_medium = pad_payload_to_bucket(medium_data, buckets=[256, 1024, 4096])
        self.assertEqual(len(padded_medium), 1024)

        unpadded_medium = unpad_payload_from_bucket(padded_medium)
        self.assertEqual(unpadded_medium, medium_data)

    def test_covert_structural_mimicry(self):
        original_dict = {
            "cif": "on",
            "text": "SecretMessageText",
            "id": "abc123id",
            "self_text": "SelfText",
            "recip_text": "RecipText",
            "public": "PubKeyB64"
        }

        # Applica il camuffamento
        covert = apply_covert_mimicry(original_dict)

        # Verifica che i nomi espliciti siano stati nascosti
        self.assertNotIn("cif", covert)
        self.assertNotIn("text", covert)
        self.assertNotIn("id", covert)
        self.assertNotIn("self_text", covert)
        self.assertNotIn("recip_text", covert)
        self.assertNotIn("public", covert)

        # Verifica che siano presenti i nuovi campi camuffati
        self.assertEqual(covert.get("evt"), "on")
        self.assertEqual(covert.get("txt"), "SecretMessageText")
        self.assertEqual(covert.get("ref"), "abc123id")

        # Ripristina il dizionario
        reconstituted = revert_covert_mimicry(covert)
        self.assertEqual(reconstituted, original_dict)

    def test_legacy_revert_mimicry_pass_through(self):
        legacy_dict = {
            "cif": "on",
            "text": "LegacyMessage",
            "id": "legacy_id"
        }
        reconstituted = revert_covert_mimicry(legacy_dict)
        self.assertEqual(reconstituted, legacy_dict)

    def test_create_decoy_payload(self):
        decoy = create_decoy_payload()
        self.assertEqual(decoy.get("cif"), "dummy")
        self.assertTrue(len(decoy.get("text", "")) > 0)
        self.assertTrue(len(decoy.get("id", "")) > 0)

    def test_end_to_end_crypto_dpi_integration(self):
        pub_b64, priv_b64 = genera_chiavi()
        self.assertIsNotNone(pub_b64)
        self.assertIsNotNone(priv_b64)

        message = "Messaggio segreto di prova Anti-DPI!"

        # Cifra il messaggio
        ciphertext_b64 = cifra_payload(message, [pub_b64])
        self.assertIsNotNone(ciphertext_b64)

        # Ispeziona la struttura esterna serializzata: le chiavi visibili devono essere camuffate
        raw_json_str = base64.b64decode(ciphertext_b64).decode('utf-8')
        raw_json = json.loads(raw_json_str)

        # Non deve contenere la chiave 'ephemeral_pub' o 'data' in chiaro
        self.assertNotIn("ephemeral_pub", raw_json)
        self.assertIn("dat", raw_json)

        # Decifra il messaggio
        decrypted_bytes = decifra_payload(ciphertext_b64, [priv_b64])
        self.assertIsNotNone(decrypted_bytes)
        self.assertEqual(decrypted_bytes.decode('utf-8'), message)


if __name__ == '__main__':
    unittest.main()
