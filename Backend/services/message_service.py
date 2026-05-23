import traceback
import asyncio
import json
import tempfile
import shutil
import os
import secrets
import mimetypes
import io
import time
import hashlib
import base64

from fastapi import HTTPException
from telethon.tl.types import DocumentAttributeFilename

from core.config import pepper
from services.auth_service import is_logged_in
from services.telegram_service import split_message
from services.user_service import set_user_vault
from services.crypto_service import cifra_vault

from core.double_ratchet import generate_dh
from services.double_ratchet_service import load_ratchet_state, save_ratchet_state, envelope_encrypt

CAPTION_LIMIT = 1024
MESSAGE_LIMIT = 4096
MIN_UPLOAD_BPS = 32 * 1024

async def send_dr_init_logic(chat_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    if not client.is_connected(): await client.connect()

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    
    state = load_ratchet_state(username, False, chat_id_hash, data['data']['masterkey'])
    if state: return {"status": "ok"}

    priv, pub = generate_dh()
    
    chat_data = data['data'].setdefault('chats', {}).setdefault(chat_id_hash, {})
    chat_data['pending_dr_init_priv'] = base64.b64encode(priv).decode('utf-8')
    chat_data['pending_dr_init_pub'] = base64.b64encode(pub).decode('utf-8')
    
    data_to_save = data['data'].copy()
    data_to_save.pop('masterkey', None)
    vault_cifrato = cifra_vault(data_to_save, data['data']['masterkey'])
    set_user_vault(username, vault_cifrato)
    
    payload = {"cif": "dr_init", "pub": base64.b64encode(pub).decode('utf-8')}
    await client.send_message(chat_id, json.dumps(payload))
    return {"status": "pending"}

async def wait_for_dr_state(username, is_group, chat_id_hash, masterkey, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = load_ratchet_state(username, is_group, chat_id_hash, masterkey)
        if state: return state
        await asyncio.sleep(0.5)
    return None

async def delete_message_logic(chat_id: int, message_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    if not client.is_connected(): await client.connect()
    try:
        await client.delete_messages(chat_id, [message_id], revoke=True)
        return {"status": "ok"}
    except Exception:
        raise HTTPException(status_code=502, detail="Non permesso")

async def send_file_logic(chat_id: int, text: str, cryph: bool, group: bool, file, filename: str, content_type: str, login_session: str):
    raise HTTPException(status_code=501, detail="L'invio di file crittografati con Double Ratchet sarà supportato in un aggiornamento futuro.")

async def send_message_logic(chat_id: int, text: str, cryph: bool, group: bool, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    if not client.is_connected(): await client.connect()

    if not cryph:
        if len(text) > 4096:
            for t in split_message(text): await client.send_message(chat_id, t)
        else:
            await client.send_message(chat_id, text)
        return {"status": "ok"}
        
    id_message = secrets.token_hex(16)
    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    
    state = load_ratchet_state(username, group, chat_id_hash, data['data']['masterkey'])
    
    if not state:
        await send_dr_init_logic(chat_id, login_session)
        state = await wait_for_dr_state(username, group, chat_id_hash, data['data']['masterkey'])
        if not state:
            raise HTTPException(status_code=503, detail="Inizializzazione Double Ratchet in corso. L'utente deve essere online per accettare l'handshake. Riprova tra poco.")

    da_cifrare = {"text": text, "timestamp": time.time(), "id": id_message}
    json_da_cifrare = json.dumps(da_cifrare, sort_keys=True).encode('utf-8')
    
    recipients_states = {chat_id_hash: state}
    envelope, updated_states = envelope_encrypt(json_da_cifrare, recipients_states)
    
    for uid, s in updated_states.items():
        save_ratchet_state(username, group, uid, data['data']['masterkey'], s)
        
    finale = {"cif": "dr_msg", "envelope": envelope}
    
    try:
        await client.send_message(chat_id, json.dumps(finale))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    return {"status": "ok"}
