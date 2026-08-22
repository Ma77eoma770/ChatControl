import os
import secrets
import time
from core.config import dpi_buckets, enable_dpi_obfuscation

DEFAULT_BUCKETS = dpi_buckets if dpi_buckets else [256, 1024, 4096, 16384, 65536]

# Map per il Covert Structural Mimicry
OUTBOUND_KEY_MAP = {
    "cif": "evt",
    "text": "txt",
    "id": "ref",
    "self_text": "s_txt",
    "recip_text": "r_txt",
    "public": "pk",
    "ephemeral_pub": "e_pk",
    "deks": "dks",
    "data": "dat",
    "header": "hdr",
    "dh_pub": "d_pk",
    "ciphertext": "c_txt",
}

INBOUND_KEY_MAP = {v: k for k, v in OUTBOUND_KEY_MAP.items()}



def pad_payload_to_bucket(payload_bytes: bytes, buckets: list[int] | None = None) -> bytes:
    """
    Allinea la dimensione di payload_bytes al bucket più vicino usando byte di rumore casuale (os.urandom).
    Formato pacchetto padrato: [4B original_len (big-endian)] [payload_bytes] [random noise bytes]
    """
    if not payload_bytes:
        return payload_bytes

    if buckets is None:
        buckets = DEFAULT_BUCKETS

    orig_len = len(payload_bytes)
    needed = orig_len + 4

    # Trova il bucket più piccolo che possa contenere needed
    target_size = None
    for b in sorted(buckets):
        if b >= needed:
            target_size = b
            break

    # Se supera il bucket più grande, arrotonda al multiplo superiore di 65536 (64KB)
    if target_size is None:
        chunk_block = 65536
        target_size = ((needed + chunk_block - 1) // chunk_block) * chunk_block

    pad_len = target_size - needed
    noise = os.urandom(pad_len)
    return orig_len.to_bytes(4, byteorder='big') + payload_bytes + noise


def unpad_payload_from_bucket(padded_bytes: bytes) -> bytes:
    """
    Estrae il payload originale dal pacchetto padrato rimuovendo i byte di rumore.
    """
    if not padded_bytes or len(padded_bytes) < 4:
        return padded_bytes

    try:
        orig_len = int.from_bytes(padded_bytes[:4], byteorder='big')
        if 0 <= orig_len <= len(padded_bytes) - 4:
            return padded_bytes[4:4 + orig_len]
    except Exception:
        pass

    return padded_bytes


def apply_covert_mimicry(data: dict) -> dict:
    """
    Trasforma le chiavi esplicite di un dizionario JSON nei corrispondenti nomi camuffati per la rete.
    """
    if not isinstance(data, dict):
        return data

    covert_data = {}
    for key, value in data.items():
        covert_key = OUTBOUND_KEY_MAP.get(key, key)
        covert_data[covert_key] = value

    return covert_data


def revert_covert_mimicry(data: dict) -> dict:
    """
    Ripristina le chiavi originali di un dizionario JSON camuffato ricevuto dalla rete.
    Supporta retrocompatibilità trasparente per dizionari legacy.
    """
    if not isinstance(data, dict):
        return data

    # Se contiene già chiavi esplicite come 'cif', non necessita di ripristino
    if "cif" in data:
        return data

    reconstituted = {}
    for key, value in data.items():
        original_key = INBOUND_KEY_MAP.get(key, key)
        reconstituted[original_key] = value

    return reconstituted


def create_decoy_payload() -> dict:
    """
    Genera un payload fittizio (civetta/dummy) per il traffico di inserimento e disturbo temporale.
    """
    id_message = secrets.token_hex(16)
    dummy_text = secrets.token_hex(32)
    return {
        "cif": "dummy",
        "text": dummy_text,
        "timestamp": time.time(),
        "id": id_message,
    }
