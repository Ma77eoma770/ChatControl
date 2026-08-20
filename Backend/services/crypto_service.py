import base64
import nacl.public
import nacl.secret
import nacl.utils
import nacl.exceptions
import json
import time
import os
import sqlite3
import hashlib
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from fastapi import HTTPException
from core.config import pepper
from database.sqlite import get_connection

# Magic bytes per il formato stream v3
_STREAM_MAGIC = b"CCV3"


def deriva_master_key(passphrase: str, salt: bytes | str) -> bytes:
    """
    Deriva una master key crittografica a partire da una passphrase e un salt
    utilizzando Argon2id. Restituisce la chiave in formato base64 url-safe.
    """
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    return base64.urlsafe_b64encode(raw_key)


def cifra_vault(dizionario: dict, master_key) -> str:
    """
    Cifra un dizionario Python con PyNaCl SecretBox (XSalsa20-Poly1305).
    Restituisce una stringa base64 (nonce + ciphertext) per la persistenza in SQLite.
    """
    json_data = json.dumps(dizionario).encode('utf-8')
    raw_key = base64.urlsafe_b64decode(master_key)
    box = nacl.secret.SecretBox(raw_key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(json_data, nonce)
    return base64.b64encode(nonce + encrypted.ciphertext).decode('utf-8')


def decifra_vault(blob_cifrato, master_key) -> dict:
    """
    Decifra un blob PyNaCl SecretBox restituendo il dizionario originale.
    Solleva ValueError in caso di password errata o fallimento nella decifratura.
    """
    try:
        raw_key = base64.urlsafe_b64decode(master_key)
        box = nacl.secret.SecretBox(raw_key)
        raw_blob = base64.b64decode(blob_cifrato.encode() if isinstance(blob_cifrato, str) else blob_cifrato)
        nonce = raw_blob[:nacl.secret.SecretBox.NONCE_SIZE]
        ciphertext = raw_blob[nacl.secret.SecretBox.NONCE_SIZE:]
        decrypted_bytes = box.decrypt(ciphertext, nonce)
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError("Password errata o vault non decifrabile.") from e


from services.double_ratchet import DoubleRatchetSession


def cifra_payload_dr(plaintext: str | bytes, dr_session: DoubleRatchetSession) -> str | None:
    """
    Cifra un testo o byte tramite DoubleRatchetSession e restituisce l'envelope codificato in base64 JSON.
    Restituisce None se la sessione non è in uno stato pronto per l'invio.
    """
    try:
        dr_envelope = dr_session.encrypt(plaintext)
        hdr = dr_envelope.get("header", {})
        dh_short = hdr.get("dh_pub", "")[:12]
        print(f"🔒 [DoubleRatchet ENCRYPT] dh_pub={dh_short}... n={hdr.get('n')} pn={hdr.get('pn')}")
        json_bytes = json.dumps(dr_envelope).encode('utf-8')
        return base64.b64encode(json_bytes).decode('utf-8')
    except Exception as e:
        print(f"⚠️ [DoubleRatchet ENCRYPT ERROR] {e}")
        return None


def derive_shared_secret(my_priv_b64: str, remote_pub_b64: str) -> bytes:
    """Deriva la Master Shared Secret (32 byte) tramite ECDH (X25519) ed HKDF-SHA256."""
    my_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(my_priv_b64))
    remote_pub = X25519PublicKey.from_public_bytes(base64.b64decode(remote_pub_b64))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=b"ChatControl DoubleRatchet SharedSecret"
    ).derive(my_priv.exchange(remote_pub))


def get_or_create_dr_session(
    data: dict, 
    chat_id1: int | str, 
    is_initiator: bool = True, 
    remote_pub_override: str | None = None
) -> tuple[DoubleRatchetSession | None, dict | None]:
    """
    Recupera la sessione DoubleRatchet per una chat 1:1 dal vault del contatto in SQLite.
    Se non esiste ancora, la inizializza (init_alice se initiator, init_bob se receiver) e la salva.
    Restituisce la tupla (dr_session, vault_deciphered).
    """
    if not data or 'data' not in data:
        return None, None

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()
    masterkey = data['data'].get('masterkey')
    if not masterkey:
        return None, None

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?",
                (username, chat_id_hash)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error:
        return None, None

    vault_deciphered = None
    if risultato and risultato[0]:
        try:
            vault_deciphered = decifra_vault(risultato[0], masterkey)
        except Exception:
            vault_deciphered = None

    if not vault_deciphered:
        vault_deciphered = {'user_id': chat_id1, 'username': str(chat_id1), 'chiavi': []}

    # Se dr_session è già registrato nel sub-vault del contatto
    if 'dr_session' in vault_deciphered and vault_deciphered['dr_session']:
        try:
            session = DoubleRatchetSession.from_dict(vault_deciphered['dr_session'])
            if is_initiator and session.cks is None and session.ns == 0 and session.nr == 0:
                remote_pub_b64 = remote_pub_override
                if not remote_pub_b64:
                    all_keys = vault_deciphered.get('chiavi', [])
                    active_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]
                    if active_keys:
                        remote_pub_b64 = active_keys[0]
                chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
                my_priv_b64 = chat_data.get('chiave', {}).get('privata')
                if my_priv_b64 and remote_pub_b64:
                    shared_secret = derive_shared_secret(my_priv_b64, remote_pub_b64)
                    session = DoubleRatchetSession.init_alice(shared_secret, remote_pub_b64)
                    vault_deciphered['dr_session'] = session.to_dict()
                    save_dr_session_to_vault(data, chat_id1, session, vault_deciphered)
            return session, vault_deciphered
        except Exception:
            pass

    # Recupera le chiavi per l'inizializzazione
    chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
    my_priv_b64 = chat_data.get('chiave', {}).get('privata')
    if not my_priv_b64:
        return None, vault_deciphered

    remote_pub_b64 = remote_pub_override
    if not remote_pub_b64:
        all_keys = vault_deciphered.get('chiavi', [])
        active_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]
        if active_keys:
            remote_pub_b64 = active_keys[0]

    if not remote_pub_b64:
        return None, vault_deciphered

    shared_secret = derive_shared_secret(my_priv_b64, remote_pub_b64)
    if is_initiator:
        session = DoubleRatchetSession.init_alice(shared_secret, remote_pub_b64)
    else:
        session = DoubleRatchetSession.init_bob(shared_secret, my_priv_b64)

    vault_deciphered['dr_session'] = session.to_dict()
    save_dr_session_to_vault(data, chat_id1, session, vault_deciphered)
    return session, vault_deciphered


def save_dr_session_to_vault(
    data: dict, 
    chat_id1: int | str, 
    dr_session: DoubleRatchetSession, 
    vault_deciphered: dict | None = None
) -> bool:
    """Salva lo stato aggiornato della sessione Double Ratchet nel vault del contatto in SQLite."""
    if not dr_session or not data or 'data' not in data:
        return False

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()
    masterkey = data['data'].get('masterkey')
    if not masterkey:
        return False

    if vault_deciphered is None:
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?",
                    (username, chat_id_hash)
                )
                risultato = cursor.fetchone()
                if risultato and risultato[0]:
                    vault_deciphered = decifra_vault(risultato[0], masterkey)
                else:
                    vault_deciphered = {'user_id': chat_id1, 'username': str(chat_id1), 'chiavi': []}
        except Exception:
            vault_deciphered = {'user_id': chat_id1, 'username': str(chat_id1), 'chiavi': []}

    vault_deciphered['dr_session'] = dr_session.to_dict()
    vault_cifrato = cifra_vault(vault_deciphered, masterkey)

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?) "
                "ON CONFLICT(proprietario, contatto_id) DO UPDATE SET vault = excluded.vault",
                (username, chat_id_hash, vault_cifrato)
            )
            conn.commit()
        return True
    except sqlite3.Error:
        return False


def cifra_payload(plaintext: str | bytes, public_keys: list) -> str | None:
    """
    Cifra un testo/dati binari con Envelope Encryption v3:
    ECDH X25519 per la derivazione della DEK (via HKDF-SHA256) + XSalsa20-Poly1305 per il payload.

    Attenzione: per payload di grandi dimensioni preferire cifra_payload_stream.
    Ritorna il base64 dell'envelope JSON v3, oppure None in caso di errore.
    """
    try:
        ephemeral_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        ephemeral_pub_b64 = base64.b64encode(ephemeral_priv.public_key().public_bytes_raw()).decode('utf-8')

        mmk = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        encrypted_deks = _encrypt_mmk_for_recipients(mmk, ephemeral_priv, public_keys)

        if not encrypted_deks:
            return None

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        payload_box = nacl.secret.SecretBox(mmk)
        nonce_payload = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted_payload = payload_box.encrypt(plaintext, nonce_payload)

        envelope = {
            "v": 3,
            "ephemeral_pub": ephemeral_pub_b64,
            "deks": encrypted_deks,
            "data": base64.b64encode(encrypted_payload).decode('utf-8')
        }
        return base64.b64encode(json.dumps(envelope).encode()).decode()
    except Exception:
        return None


def decifra_payload(ciphertext, candidate_privates: list, dr_session: DoubleRatchetSession | None = None) -> bytes | None:
    """
    Decifra un payload cifrato con Double Ratchet (dr_v1) o Envelope Encryption v3 (v: 3).
    candidate_privates: lista di chiavi private X25519 in formato base64.
    Ritorna i byte in chiaro oppure None se la decifratura fallisce.
    """
    try:
        raw_bytes = ciphertext.encode() if isinstance(ciphertext, str) else ciphertext
        try:
            input_bytes = base64.b64decode(raw_bytes, validate=True)
        except Exception:
            input_bytes = raw_bytes

        envelope = json.loads(input_bytes.decode('utf-8'))
        
        # Supporto Double Ratchet envelope
        if envelope.get("v") == "dr_v1":
            hdr = envelope.get("header", {})
            dh_short = hdr.get("dh_pub", "")[:12]
            print(f"🔓 [DoubleRatchet DECRYPT] dh_pub={dh_short}... n={hdr.get('n')} pn={hdr.get('pn')}")
            if dr_session:
                return dr_session.decrypt(envelope)
            elif candidate_privates and envelope.get("header", {}).get("dh_pub"):
                # Inizializza automaticamente la sessione Bob se riceve il primo messaggio DR
                dh_pub = envelope["header"]["dh_pub"]
                my_priv_b64 = candidate_privates[0]
                my_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(my_priv_b64))
                remote_pub = X25519PublicKey.from_public_bytes(base64.b64decode(dh_pub))
                shared_secret = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"\x00" * 32,
                    info=b"ChatControl DoubleRatchet SharedSecret"
                ).derive(my_priv.exchange(remote_pub))
                session = DoubleRatchetSession.init_bob(shared_secret, my_priv_b64)
                return session.decrypt(envelope)
            return None

        if envelope.get("v") != 3:
            return None

        ephemeral_pub_b64 = envelope.get("ephemeral_pub")
        encrypted_deks = envelope.get("deks", [])
        if not ephemeral_pub_b64:
            return None

        ephemeral_pub_key = X25519PublicKey.from_public_bytes(base64.b64decode(ephemeral_pub_b64))

        mmk = _decrypt_mmk_from_envelope(ephemeral_pub_key, encrypted_deks, candidate_privates)
        if not mmk:
            return None

        payload_box = nacl.secret.SecretBox(mmk)
        encrypted_data = base64.b64decode(envelope.get("data", ""))
        return payload_box.decrypt(encrypted_data)
    except Exception:
        return None


def genera_chiavi() -> tuple[str | None, str | None]:
    """
    Genera una coppia di chiavi X25519 (Curve25519).
    Ritorna (pubblica_b64, privata_b64) oppure (None, None) in caso di errore.
    """
    try:
        private_key = X25519PrivateKey.from_private_bytes(os.urandom(32))
        pubblica = base64.b64encode(private_key.public_key().public_bytes_raw()).decode('utf-8')
        privata = base64.b64encode(private_key.private_bytes_raw()).decode('utf-8')
        return pubblica, privata
    except Exception:
        return None, None


def is_valid_public_key(key: str) -> bool:
    """
    Verifica se una stringa rappresenta una chiave pubblica X25519 valida (32 byte, base64).
    """
    try:
        decoded = base64.b64decode(key, validate=True)
        return len(decoded) == nacl.public.PublicKey.SIZE
    except Exception:
        return False


def store_public_key_in_vault(
    user_data,
    chat_id: int,
    sender_id,
    public_key: str,
    msg_date=None,
    is_group: bool | None = None,
    group_title: str | None = None,
    sender_username: str | None = None,
) -> bool:
    """
    Salva la chiave pubblica ricevuta all'interno del vault crittografato dell'utente,
    tracciando le rotazioni (data inizio/fine di validità).
    """
    if not user_data or not public_key:
        return False

    if is_group is None:
        try:
            is_group = int(chat_id) < 0
        except Exception:
            is_group = False

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    vault_deciphered = None
    insert_new_vault = False

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            table = 'contatti_gruppo' if is_group else 'contatti'
            id_col = 'gruppo_id' if is_group else 'contatto_id'
            cursor.execute(f"SELECT vault FROM {table} WHERE proprietario = ? AND {id_col} = ?", (username, chat_id_cif))
            risultato = cursor.fetchone()

            if not risultato or not risultato[0]:
                insert_new_vault = True
                if is_group:
                    vault_deciphered = {'gruppo_id': chat_id, 'gruppo_nome': group_title or 'Gruppo', 'partecipanti': {}}
                else:
                    vault_deciphered = {'user_id': chat_id, 'username': sender_username or str(chat_id), 'chiavi': []}
            else:
                vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
    except sqlite3.Error:
        return False

    # Verifica che la chiave non sia già presente
    existing_keys = set()
    if is_group:
        for p in vault_deciphered.get('partecipanti', {}).values():
            if p.get('chiave', {}).get('chiave'):
                existing_keys.add(p['chiave']['chiave'])
            existing_keys.update(k['chiave'] for k in p.get('chiavi', []) if k.get('chiave'))
    else:
        existing_keys.update(k['chiave'] for k in vault_deciphered.get('chiavi', []) if k.get('chiave'))

    if public_key in existing_keys:
        return False

    new_key_timestamp = msg_date.timestamp() if msg_date else time.time()
    new_key = {'chiave': public_key, 'inizio': new_key_timestamp, 'fine': None}

    if is_group:
        sender_id_str = str(sender_id) if sender_id is not None else ''
        partecipanti = vault_deciphered.setdefault('partecipanti', {})
        if sender_id_str not in partecipanti:
            partecipanti[sender_id_str] = {'chiave': {}, 'chiavi': []}

        current_key = partecipanti[sender_id_str].get('chiave', {})
        if current_key and current_key.get('chiave'):
            current_key['fine'] = new_key_timestamp - 1
            partecipanti[sender_id_str].setdefault('chiavi', []).append(current_key)
        partecipanti[sender_id_str]['chiave'] = new_key
    else:
        chiavi_list = vault_deciphered.get('chiavi', [])
        for chiave_info in chiavi_list:
            if chiave_info.get('fine') is None:
                chiave_info['fine'] = new_key_timestamp - 1
        chiavi_list.append(new_key)
        vault_deciphered['chiavi'] = chiavi_list

    vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            table = 'contatti_gruppo' if is_group else 'contatti'
            id_col = 'gruppo_id' if is_group else 'contatto_id'
            if insert_new_vault:
                cursor.execute(f"INSERT INTO {table} (proprietario, {id_col}, vault) VALUES (?, ?, ?)", (username, chat_id_cif, vault_cifrato))
            else:
                cursor.execute(f"UPDATE {table} SET vault = ? WHERE proprietario = ? AND {id_col} = ?", (vault_cifrato, username, chat_id_cif))
            conn.commit()
    except sqlite3.Error:
        return False

    return True


def get_group_chyper_keys(data, chat_id1) -> list[str]:
    """
    Recupera le chiavi pubbliche attive di tutti i partecipanti di un gruppo,
    inclusa la propria chiave pubblica, per la cifratura del messaggio.
    """
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?",
                (username, chat_id)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = []
    if risultato and risultato[0]:
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        all_keys = []
        for p in vault_deciphered.get('partecipanti', {}).values():
            if p.get('chiave', {}).get('chiave'):
                all_keys.append(p['chiave'])
            all_keys.extend(p.get('chiavi', []))
        recipient_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
            user_pubblica = chat_data['chiave']['pubblica']
            if user_pubblica and user_pubblica not in recipient_keys:
                recipient_keys.append(user_pubblica)

    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")
    return recipient_keys


def get_chat_chyper_keys(data, chat_id1) -> list[str]:
    """
    Recupera la chiave pubblica attiva del destinatario di una chat 1:1,
    più la propria chiave pubblica, per la cifratura del messaggio.
    """
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?",
                (username, chat_id)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = []
    if risultato and risultato[0]:
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        all_keys = vault_deciphered.get('chiavi', [])
        recipient_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]

    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
            user_pubblica = chat_data['chiave']['pubblica']
            if user_pubblica and user_pubblica not in recipient_keys:
                recipient_keys.append(user_pubblica)

    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")
    return recipient_keys


# ---------------------------------------------------------------------------
# Helpers interni per DEK (non esportati)
# ---------------------------------------------------------------------------

def _encrypt_mmk_for_recipients(mmk: bytes, ephemeral_priv: X25519PrivateKey, public_keys: list) -> list[str]:
    """Cifra la Master Message Key per ciascuna chiave pubblica destinataria."""
    encrypted_deks = []
    for pk_b64 in public_keys:
        try:
            pub_key = X25519PublicKey.from_public_bytes(base64.b64decode(pk_b64))
            shared_key = ephemeral_priv.exchange(pub_key)
            derived_dek = HKDF(
                algorithm=hashes.SHA256(),
                length=nacl.secret.SecretBox.KEY_SIZE,
                salt=None,
                info=b"ChatControl Message DEK HKDF"
            ).derive(shared_key)
            dek_box = nacl.secret.SecretBox(derived_dek)
            nonce_dek = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            enc_mmk = dek_box.encrypt(mmk, nonce_dek)
            encrypted_deks.append(base64.b64encode(nonce_dek + enc_mmk.ciphertext).decode('utf-8'))
        except Exception:
            continue
    return encrypted_deks


def _decrypt_mmk_from_envelope(
    ephemeral_pub_key: X25519PublicKey,
    encrypted_deks: list,
    candidate_privates: list
) -> bytes | None:
    """Tenta di decifrare la Master Message Key usando le chiavi private candidate."""
    for priv_b64 in candidate_privates:
        try:
            priv_key = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
            shared_key = priv_key.exchange(ephemeral_pub_key)
            derived_dek = HKDF(
                algorithm=hashes.SHA256(),
                length=nacl.secret.SecretBox.KEY_SIZE,
                salt=None,
                info=b"ChatControl Message DEK HKDF"
            ).derive(shared_key)
            dek_box = nacl.secret.SecretBox(derived_dek)
            for enc_mmk_b64 in encrypted_deks:
                try:
                    full_enc_mmk = base64.b64decode(enc_mmk_b64)
                    nonce_dek = full_enc_mmk[:nacl.secret.SecretBox.NONCE_SIZE]
                    ciphertext_mmk = full_enc_mmk[nacl.secret.SecretBox.NONCE_SIZE:]
                    return dek_box.decrypt(ciphertext_mmk, nonce_dek)
                except nacl.exceptions.CryptoError:
                    continue
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Stream v3 — cifratura e decifratura
# ---------------------------------------------------------------------------

def cifra_payload_stream(input_generator, public_keys: list):
    """
    Cifra in streaming usando Envelope Encryption v3 (CCV3).

    Formato binario del frame:
      [4B magic "CCV3"] [4B envelope_len] [envelope JSON] ([4B chunk_len] [chunk cifrato])*

    L'input deve essere un generatore (sync) che produce chunk bytes.
    Ritorna un generatore sync che produce i frame binari cifrati.
    """
    ephemeral_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
    ephemeral_pub_b64 = base64.b64encode(ephemeral_priv.public_key().public_bytes_raw()).decode('utf-8')

    mmk = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    encrypted_deks = _encrypt_mmk_for_recipients(mmk, ephemeral_priv, public_keys)

    if not encrypted_deks:
        raise ValueError("Nessuna chiave pubblica valida per la cifratura.")

    envelope = {
        "v": 3,
        "ephemeral_pub": ephemeral_pub_b64,
        "deks": encrypted_deks
    }
    envelope_bytes = json.dumps(envelope).encode('utf-8')
    yield _STREAM_MAGIC + len(envelope_bytes).to_bytes(4, byteorder='big') + envelope_bytes

    payload_box = nacl.secret.SecretBox(mmk)
    for chunk_data in input_generator:
        if not chunk_data:
            continue
        nonce_payload = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted_chunk = payload_box.encrypt(chunk_data, nonce_payload)
        yield len(encrypted_chunk).to_bytes(4, byteorder='big') + encrypted_chunk


async def _read_exact(iterator, n: int, buffer: bytearray) -> bytes | None:
    """Legge esattamente n byte dallo stream (async o sync), usando il buffer interno."""
    is_async = hasattr(iterator, "__anext__")
    while len(buffer) < n:
        try:
            chunk = await iterator.__anext__() if is_async else next(iterator)
            if not chunk:
                break
            buffer.extend(chunk)
        except (StopAsyncIteration, StopIteration):
            break
    if len(buffer) < n:
        return None
    res = bytes(buffer[:n])
    del buffer[:n]
    return res


async def decifra_payload_stream(async_iterator, candidate_privates: list):
    """
    Decifra uno stream cifrato con cifra_payload_stream (formato CCV3).

    Accetta un Async Generator o un iteratore sync compatibile.
    Ritorna un async generator che produce i chunk decifrati in chiaro.

    Solleva ValueError se il magic non corrisponde o la decifratura fallisce.
    """
    buffer = bytearray()

    magic = await _read_exact(async_iterator, 4, buffer)
    if magic != _STREAM_MAGIC:
        raise ValueError(f"Magic non valido: atteso CCV3, ricevuto {magic!r}")

    env_len_bytes = await _read_exact(async_iterator, 4, buffer)
    if not env_len_bytes:
        raise ValueError("Stream terminato prima dell'header envelope")
    env_len = int.from_bytes(env_len_bytes, byteorder='big')

    envelope_bytes = await _read_exact(async_iterator, env_len, buffer)
    if not envelope_bytes:
        raise ValueError("Stream interrotto durante la lettura dell'envelope")

    envelope = json.loads(envelope_bytes.decode('utf-8'))
    if envelope.get("v") != 3:
        raise ValueError(f"Versione envelope non supportata: {envelope.get('v')}")

    ephemeral_pub_b64 = envelope.get("ephemeral_pub")
    encrypted_deks = envelope.get("deks", [])
    if not ephemeral_pub_b64:
        raise ValueError("Chiave pubblica effimera mancante nell'envelope")

    ephemeral_pub_key = X25519PublicKey.from_public_bytes(base64.b64decode(ephemeral_pub_b64))
    mmk = _decrypt_mmk_from_envelope(ephemeral_pub_key, encrypted_deks, candidate_privates)
    if not mmk:
        raise ValueError("Impossibile decifrare l'envelope con le chiavi fornite")

    payload_box = nacl.secret.SecretBox(mmk)

    while True:
        chunk_len_bytes = await _read_exact(async_iterator, 4, buffer)
        if not chunk_len_bytes:
            break
        chunk_len = int.from_bytes(chunk_len_bytes, byteorder='big')
        encrypted_chunk = await _read_exact(async_iterator, chunk_len, buffer)
        if not encrypted_chunk:
            break
        yield payload_box.decrypt(encrypted_chunk)


async def estrai_metadata_da_stream(async_iterator, candidate_privates: list) -> str | None:
    """
    Legge la prima parte di uno stream CCV3 per estrarre i metadata JSON.

    Il primo chunk decifrato deve avere il formato:
      [4B metadata_size (big-endian)] [metadata_size byte JSON UTF-8]

    Ritorna la stringa JSON dei metadata, oppure None in caso di errore.
    """
    try:
        decrypted_stream = decifra_payload_stream(async_iterator, candidate_privates)
        first_chunk = await decrypted_stream.__anext__()
        if first_chunk and len(first_chunk) >= 4:
            metadata_size = int.from_bytes(first_chunk[:4], byteorder='big')
            if 0 < metadata_size <= len(first_chunk) - 4:
                return first_chunk[4:4 + metadata_size].decode('utf-8')
    except Exception:
        pass
    return None
