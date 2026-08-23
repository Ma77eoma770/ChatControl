import sys
import os
import unittest
import base64
import json
import asyncio

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.dpi_service import (
    pad_payload_to_bucket, unpad_payload_from_bucket,
    apply_covert_mimicry, revert_covert_mimicry,
    create_decoy_payload, PAD_MAGIC, pad_outer_payload
)
from services.crypto_service import (
    genera_chiavi, cifra_payload, decifra_payload,
    cifra_payload_stream, decifra_payload_stream
)


class TestDPIService(unittest.TestCase):

    def test_pad_and_unpad_buckets(self):
        # 1. Payload breve (<256 byte) -> deve essere padrato a 256 byte
        short_data = b"Hello Anti-DPI World!"
        padded_short = pad_payload_to_bucket(short_data, buckets=[256, 1024, 4096])
        self.assertEqual(len(padded_short), 256)
        self.assertTrue(padded_short.startswith(PAD_MAGIC))

        unpadded_short = unpad_payload_from_bucket(padded_short)
        self.assertEqual(unpadded_short, short_data)

        # 2. Payload medio (>256 byte, <1024 byte) -> deve essere padrato a 1024 byte
        medium_data = b"A" * 300
        padded_medium = pad_payload_to_bucket(medium_data, buckets=[256, 1024, 4096])
        self.assertEqual(len(padded_medium), 1024)
        self.assertTrue(padded_medium.startswith(PAD_MAGIC))

        unpadded_medium = unpad_payload_from_bucket(padded_medium)
        self.assertEqual(unpadded_medium, medium_data)

    def test_unpad_safety_for_non_padded_data(self):
        # Dati grezzi non padrati che non contengono PAD_MAGIC non devono essere troncati
        raw_unpadded = b"\x00\x00\x00\x021234567890"
        result = unpad_payload_from_bucket(raw_unpadded)
        self.assertEqual(result, raw_unpadded)

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

    def test_recursive_covert_mimicry(self):
        nested_dict = {
            "v": "dr_v1",
            "header": {
                "dh_pub": "DH_PUB_KEY_B64",
                "n": 1,
                "pn": 0
            },
            "ciphertext": "CYPHERTEXT_B64",
            "deks": [
                {"ephemeral_pub": "E_PUB_1", "data": "DATA_1"}
            ]
        }

        covert = apply_covert_mimicry(nested_dict)

        # Il livello primario deve essere camuffato
        self.assertIn("hdr", covert)
        self.assertNotIn("header", covert)
        self.assertIn("c_txt", covert)
        self.assertNotIn("ciphertext", covert)

        # I sotto-dizionari e le liste annidate devono essere ricorsivamente camuffati
        self.assertIn("d_pk", covert["hdr"])
        self.assertNotIn("dh_pub", covert["hdr"])
        self.assertIn("e_pk", covert["dks"][0])
        self.assertNotIn("ephemeral_pub", covert["dks"][0])
        self.assertIn("dat", covert["dks"][0])
        self.assertNotIn("data", covert["dks"][0])

        # Il ripristino deve ricostruire esattamente la struttura originale annidata
        reconstituted = revert_covert_mimicry(covert)
        self.assertEqual(reconstituted, nested_dict)

    def test_outer_payload_mimicry_and_reversion(self):
        # 1. Messaggio finale di testo
        finale = {
            "cif": "on",
            "text": "EncryptedTextB64",
            "id": "EncryptedIdB64",
            "self_text": "SelfTextB64",
            "recip_text": "RecipTextB64"
        }
        covert_finale = apply_covert_mimicry(finale)
        self.assertNotIn("cif", covert_finale)
        self.assertEqual(covert_finale["evt"], "on")
        self.assertEqual(covert_finale["txt"], "EncryptedTextB64")
        self.assertEqual(covert_finale["ref"], "EncryptedIdB64")

        reverted_finale = revert_covert_mimicry(covert_finale)
        self.assertEqual(reverted_finale, finale)

        # 2. Messaggio di scambio chiavi
        key_payload = {"cif": "in", "public": "PubKeyB64"}
        covert_key = apply_covert_mimicry(key_payload)
        self.assertEqual(covert_key["evt"], "in")
        self.assertEqual(covert_key["pk"], "PubKeyB64")
        self.assertEqual(revert_covert_mimicry(covert_key), key_payload)

        # 3. Caption file
        caption_payload = {"cif": "file"}
        covert_caption = apply_covert_mimicry(caption_payload)
        self.assertEqual(covert_caption["evt"], "file")
        self.assertEqual(revert_covert_mimicry(covert_caption), caption_payload)

    def test_pad_outer_payload(self):
        sample_dict = {"evt": "on", "txt": "ciphertext", "ref": "id"}
        padded = pad_outer_payload(sample_dict, buckets=[512, 1024, 2048, 4096])

        # La stringa JSON risultante deve corrispondere esattamente al primo bucket utile (512 byte)
        json_str = json.dumps(padded)
        self.assertEqual(len(json_str), 512)
        self.assertIn("p", padded)

        # Il ripristino delle chiavi deve ignorare/funzionare correttamente con la chiave 'p'
        reverted = revert_covert_mimicry(padded)
        self.assertEqual(reverted.get("cif"), "on")
        self.assertEqual(reverted.get("text"), "ciphertext")
        self.assertEqual(reverted.get("id"), "id")

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

        covert_decoy = apply_covert_mimicry(decoy)
        self.assertEqual(covert_decoy.get("evt"), "dummy")
        self.assertEqual(revert_covert_mimicry(covert_decoy), decoy)

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

    def test_stream_encryption_dpi_mimicry(self):
        async def run_async_stream_test():
            pub_b64, priv_b64 = genera_chiavi()

            def input_gen():
                yield b"Stream chunk 1 "
                yield b"Stream chunk 2"

            cipher_chunks = list(cifra_payload_stream(input_gen(), [pub_b64]))
            self.assertTrue(len(cipher_chunks) >= 3)  # magic + header + chunks

            # Verifica che l'envelope header sia stato camuffato con Anti-DPI
            magic = cipher_chunks[0][:4]
            self.assertEqual(magic, b"CCV3")
            env_len = int.from_bytes(cipher_chunks[0][4:8], byteorder='big')
            env_json_bytes = cipher_chunks[0][8:8 + env_len]
            env_dict = json.loads(env_json_bytes.decode('utf-8'))

            # Verifica camuffamento chiavi dello stream header
            self.assertIn("e_pk", env_dict)
            self.assertNotIn("ephemeral_pub", env_dict)
            self.assertIn("dks", env_dict)
            self.assertNotIn("deks", env_dict)

            # Decifra lo stream e verifica che i chunk ricostruiti corrispondano
            async def async_cipher_gen():
                for chunk in cipher_chunks:
                    yield chunk

            decrypted_stream = decifra_payload_stream(async_cipher_gen(), [priv_b64])
            reconstituted_bytes = bytearray()
            async for chunk in decrypted_stream:
                reconstituted_bytes.extend(chunk)

            self.assertEqual(bytes(reconstituted_bytes), b"Stream chunk 1 Stream chunk 2")

        asyncio.run(run_async_stream_test())


if __name__ == '__main__':
    unittest.main()

