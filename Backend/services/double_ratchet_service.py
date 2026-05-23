import json
import base64
import os
import sqlite3
from fastapi import HTTPException
from database.sqlite import get_connection
from core.double_ratchet import (
    ratchet_encrypt, ratchet_decrypt, state_to_dict, state_from_dict, encrypt_aead, decrypt_aead
)
from services.crypto_service import decifra_vault, cifra_vault

def load_ratchet_state(username: str, is_group: bool, chat_id_cif: str, masterkey: str) -> dict | None:
    """Carica e decifra lo stato del Ratchet dal database."""
    table = 'sessioni_gruppo' if is_group else 'sessioni_ratchet'
    id_col = 'gruppo_id' if is_group else 'contatto_id'
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT ratchet_vault FROM {table} WHERE proprietario = ? AND {id_col} = ?", (username, chat_id_cif))
            res = cursor.fetchone()
            if res and res[0]:
                vault = decifra_vault(res[0], masterkey)
                return state_from_dict(vault.get('state', {}))
    except Exception as e:
        print(f"[DOUBLE RATCHET DB] Errore caricamento stato per {username}: {e}")
    return None

def save_ratchet_state(username: str, is_group: bool, chat_id_cif: str, masterkey: str, state: dict):
    """Cifra e salva lo stato del Ratchet nel database."""
    table = 'sessioni_gruppo' if is_group else 'sessioni_ratchet'
    id_col = 'gruppo_id' if is_group else 'contatto_id'
    
    vault_dict = {"state": state_to_dict(state)}
    vault_cifrato = cifra_vault(vault_dict, masterkey)
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT 1 FROM {table} WHERE proprietario = ? AND {id_col} = ?", (username, chat_id_cif))
            if cursor.fetchone():
                cursor.execute(f"UPDATE {table} SET ratchet_vault = ? WHERE proprietario = ? AND {id_col} = ?", (vault_cifrato, username, chat_id_cif))
            else:
                cursor.execute(f"INSERT INTO {table} (proprietario, {id_col}, ratchet_vault) VALUES (?, ?, ?)", (username, chat_id_cif, vault_cifrato))
            conn.commit()
    except Exception as e:
        print(f"[DOUBLE RATCHET DB] Errore salvataggio stato per {username}: {e}")
        raise HTTPException(status_code=500, detail="Errore salvataggio stato Ratchet")

def envelope_encrypt(plaintext_bytes: bytes, recipients_states: dict) -> tuple[dict, dict]:
    """
    Cifra un payload con Envelope Encryption usando il Double Ratchet per proteggere la Payload Key.
    recipients_states: { 'user_id_cifrato': ratchet_state_dict, ... }
    Ritorna:
      - envelope (dict): L'oggetto JSON pronto da inviare.
      - updated_states (dict): Gli stati Ratchet aggiornati dopo l'avanzamento.
    """
    print(f"[DOUBLE RATCHET ENVELOPE] Inizio Envelope Encryption per {len(recipients_states)} destinatari.")
    
    # 1. Genera la Payload Key simmetrica (per il testo del messaggio)
    payload_key = os.urandom(32)
    
    # 2. Cifra il corpo del messaggio con la Payload Key
    encrypted_body = encrypt_aead(payload_key, plaintext_bytes, b"")
    
    # 3. Per ogni destinatario, cifra la Payload Key con la sua sessione Double Ratchet
    headers = {}
    updated_states = {}
    
    for user_id, state in recipients_states.items():
        print(f"[DOUBLE RATCHET ENVELOPE] Cifratura Payload Key per destinatario {user_id[:8]}...")
        # L'header ratchet (Ns, PN, DH) viene generato e la key cifrata
        header, enc_payload_key_b64 = ratchet_encrypt(state, payload_key, ad=b"")
        
        headers[user_id] = {
            "ratchet_header": header,
            "enc_key": enc_payload_key_b64
        }
        updated_states[user_id] = state
        
    envelope = {
        "v": "DR-1", # Versione Double Ratchet 1
        "headers": headers,
        "body": base64.b64encode(encrypted_body).decode('utf-8')
    }
    
    print("[DOUBLE RATCHET ENVELOPE] Envelope Encryption completata con successo.")
    return envelope, updated_states

def envelope_decrypt(envelope: dict, my_user_id: str, my_state: dict) -> tuple[bytes, dict]:
    """
    Decifra un envelope Double Ratchet.
    Ritorna:
      - plaintext (bytes): Il contenuto decifrato.
      - updated_state (dict): Lo stato Ratchet aggiornato post-decifratura.
    Solleva eccezioni in caso di fallimento o desync.
    """
    if envelope.get("v") != "DR-1":
        raise ValueError(f"Versione Envelope non supportata: {envelope.get('v')}")
        
    headers = envelope.get("headers", {})
    if my_user_id not in headers:
        raise ValueError("Nessun header trovato per questo utente nell'envelope")
        
    my_header_data = headers[my_user_id]
    ratchet_header = my_header_data["ratchet_header"]
    enc_payload_key_b64 = my_header_data["enc_key"]
    
    print(f"[DOUBLE RATCHET ENVELOPE] Tentativo di recupero Payload Key dall'envelope...")
    payload_key = ratchet_decrypt(my_state, ratchet_header, enc_payload_key_b64, ad=b"")
    
    print(f"[DOUBLE RATCHET ENVELOPE] Payload Key recuperata. Decifratura del body in corso...")
    encrypted_body = base64.b64decode(envelope["body"])
    
    plaintext = decrypt_aead(payload_key, encrypted_body, b"")
    print(f"[DOUBLE RATCHET ENVELOPE] Body decifrato con successo.")
    
    return plaintext, my_state
