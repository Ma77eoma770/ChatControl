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

from fastapi import HTTPException
from telethon.tl.types import DocumentAttributeFilename

from core.config import pepper
from services.auth_service import is_logged_in
from services.crypto_service import (
    cifra_payload, genera_chiavi, cifra_vault, 
    get_chat_chyper_keys, get_group_chyper_keys,
    cifra_payload_stream, cifra_payload_dr,
    get_or_create_dr_session, save_dr_session_to_vault
)
from services.telegram_service import split_message
from services.user_service import set_user_vault

CAPTION_LIMIT = 1024
MESSAGE_LIMIT = 4096
MIN_UPLOAD_BPS = 32 * 1024

async def wait_for_public_key_message(client, chat_id: int, public_key: str, timeout: float = 2.0, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            messages = await client.get_messages(chat_id, limit=10)
        except Exception:
            messages = []
        for msg in messages or []:
            text = getattr(msg, "message", None) or getattr(msg, "text", None) or ""
            if '"cif"' in text and '"in"' in text and public_key in text:
                return True
        await asyncio.sleep(interval)
    return False

def _build_encrypted_payload(metadata: dict, file_content: bytes, recipient_keys: list) -> bytes:
    """
    Costruisce il blob crittografato V1 in memoria per dati di piccole dimensioni.
    """
    def _generator():
        json_metadata = json.dumps(metadata, sort_keys=True)
        metadata_bytes = json_metadata.encode('utf-8')
        metadata_size = len(metadata_bytes)
        yield metadata_size.to_bytes(4, byteorder='big') + metadata_bytes
        yield file_content
        
    out = bytearray()
    for chunk in cifra_payload_stream(_generator(), recipient_keys):
        out.extend(chunk)
    return bytes(out)

async def delete_message_logic(chat_id: int, message_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()
    try:
        await client.delete_messages(chat_id, [message_id], revoke=True)
        fetched = await client.get_messages(chat_id, ids=message_id)
        if fetched is None or getattr(fetched, "deleted", False):
            return {"status": "ok"}
        return {"status": "not_deleted"}
    except Exception:
        raise HTTPException(status_code=502, detail="Non hai il permesso di cancellare questo messaggio")

async def send_file_logic(chat_id: int, text: str, cryph: bool, group: bool, file, filename: str, content_type: str, login_session: str):
    """
    Carica un file (e possibilmente una caption) verso Telegram.
    Sfrutta in streaming l'UploadFile per limitare la memoria.
    Se 'cryph' è True, il file viene cifrato al volo e salvato localmente
    come .dat e poi inviato.
    """
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not cryph:
        try:
            ext = os.path.splitext(filename)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                file.file.seek(0)
                shutil.copyfileobj(file.file, tmp)
                tmp_path = tmp.name

            from services.fast_telethon import upload_file
            uploaded_file = await upload_file(client, tmp_path)
            
            await client.send_file(
                chat_id,
                uploaded_file,
                caption=text,
                force_document=True,
                attributes=[DocumentAttributeFilename(filename)]
            )
            os.remove(tmp_path)
            return {"status": "ok"}
        except Exception as e:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

    else:
        id_message = secrets.token_hex(16)
        nome_file = f"{secrets.token_hex(8)}.dat"
        
        recipient_keys = get_group_chyper_keys(data, chat_id) if group else get_chat_chyper_keys(data, chat_id)
        
        try:
            guessed_mime, _ = mimetypes.guess_type(filename)
            mime_type = guessed_mime or content_type or "application/octet-stream"

            file.file.seek(0, 2)
            file_size = file.file.tell()
            file.file.seek(0)

            metadata = {
                "filename": filename,
                "cif": "file",
                "text": text,
                "mime": mime_type,
                "size": file_size,
                "timestamp": time.time(),
                "id": id_message
            }

            def _chunk_generator():
                json_metadata = json.dumps(metadata, sort_keys=True)
                metadata_bytes = json_metadata.encode('utf-8')
                metadata_size = len(metadata_bytes)
                yield metadata_size.to_bytes(4, byteorder='big') + metadata_bytes
                
                while True:
                    chunk = file.file.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk

            caption_dict = {"cif": "file"}
            caption_str = json.dumps(caption_dict)
            if len(caption_str) > CAPTION_LIMIT:
                raise HTTPException(status_code=413, detail=f"caption troppo lunga ({len(caption_str)}>{CAPTION_LIMIT})")

            with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tmp:
                for ciphered_chunk in cifra_payload_stream(_chunk_generator(), recipient_keys):
                    tmp.write(ciphered_chunk)
                tmp_path = tmp.name

            start_time = time.monotonic()
            async def progress_cb(current, total):
                elapsed = time.monotonic() - start_time
                if elapsed >= 1.0 and (current / max(elapsed, 0.001)) < MIN_UPLOAD_BPS:
                    raise Exception("Connessione troppo lenta")

            try:
                from services.fast_telethon import upload_file
                uploaded_file = await upload_file(client, tmp_path, progress_callback=progress_cb)
                
                await client.send_file(
                    chat_id,
                    uploaded_file,
                    caption=caption_str,
                    force_document=True,
                    attributes=[DocumentAttributeFilename(nome_file)]
                )
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

            return {"status": "ok"}
            
        except HTTPException:
            raise
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

async def send_message_logic(chat_id: int, text: str, cryph: bool, group: bool, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not cryph:
        try:
            if len(text) > 4096:
                splitted_text = split_message(text)
                for t in splitted_text:
                    await client.send_message(chat_id, t)
            else:
                await client.send_message(chat_id, text)
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    else:
        id_message = secrets.token_hex(16)
        chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
        chiave_corrente_chat = chat_data.get('chiave', {})

        if not chiave_corrente_chat or not chiave_corrente_chat.get('pubblica'):
            key_response = await send_public_key_logic(chat_id, login_session)
            public_key = key_response.get("public") if isinstance(key_response, dict) else None
            if public_key:
                key_visible = await wait_for_public_key_message(client, chat_id, public_key)
                if not key_visible:
                    raise HTTPException(status_code=503, detail="Chiave non visibile in chat, riprova")
            chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
            chiave_corrente_chat = chat_data.get('chiave', {})

        inizio_corrente = chiave_corrente_chat.get('inizio') if chiave_corrente_chat else None
        if inizio_corrente:
            elapsed = time.time() - inizio_corrente
            if elapsed < 2.5:
                await asyncio.sleep(2.5 - elapsed)

        recipient_keys = get_group_chyper_keys(data, chat_id) if group else get_chat_chyper_keys(data, chat_id)

        da_cifrare = {
            "cif": "on",
            "text": text,
            "timestamp": time.time(),
            "id": id_message,
        }

        json_da_cifrare = json.dumps(da_cifrare, sort_keys=True)

        if not group:
            dr_session, vault_deciphered = get_or_create_dr_session(data, chat_id, is_initiator=True)
            text_cyp = None
            if dr_session and dr_session.cks:
                text_cyp = cifra_payload_dr(json_da_cifrare, dr_session)
                if text_cyp:
                    encrypted_id = cifra_payload(id_message, recipient_keys)
                    save_dr_session_to_vault(data, chat_id, dr_session, vault_deciphered)

            if not text_cyp:
                text_cyp = cifra_payload(json_da_cifrare, recipient_keys)
                encrypted_id = cifra_payload(id_message, recipient_keys)
        else:
            text_cyp = cifra_payload(json_da_cifrare, recipient_keys)
            encrypted_id = cifra_payload(id_message, recipient_keys)
        
        if text_cyp is None or encrypted_id is None:
            raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
        
        if len(text_cyp) + len(encrypted_id) + 11 > MESSAGE_LIMIT:
            nome_file = f"{secrets.token_hex(8)}.dat"
            message_bytes = text.encode("utf-8")
            
            message_metadata = {
                "cif": "message",
                "timestamp": time.time(),
                "id": id_message,
            }
            
            encrypted_payload = _build_encrypted_payload(message_metadata, message_bytes, recipient_keys)
            
            file_in_ram = io.BytesIO(encrypted_payload)
            file_in_ram.name = nome_file
            caption = {"cif": "message"}

            try:
                file_in_ram.seek(0)
                await client.send_file(
                    chat_id,
                    file_in_ram,
                    caption=json.dumps(caption),
                    force_document=True,
                    attributes=[DocumentAttributeFilename(nome_file)]
                )
                return {"status": "ok"}
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
            
        user_pub = chat_data.get('chiave', {}).get('pubblica') if 'chat_data' in locals() else None
        self_keys = [user_pub] if user_pub else recipient_keys
        self_cyp = cifra_payload(json_da_cifrare, self_keys)
        recip_cyp = cifra_payload(json_da_cifrare, recipient_keys)

        finale = {
            "cif": "on",
            "text": text_cyp,
            "id": encrypted_id,
            "self_text": self_cyp,
            "recip_text": recip_cyp,
        }
        
        try:
            await client.send_message(chat_id, json.dumps(finale))
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
            
    return {"status": "ok"}

async def send_public_key_logic(chat_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    chat_id_hash = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    
    if 'chats' not in data['data']:
        data['data']['chats'] = {}
    
    chat_data = data['data']['chats'].setdefault(chat_id_hash, {})
    chiave_corrente_chat = chat_data.get('chiave', {})
    
    if chiave_corrente_chat and chiave_corrente_chat.get('inizio'):
        if time.time() - chiave_corrente_chat.get('inizio', 0) < 10:
            raise HTTPException(status_code=409, detail="Aspetta più tempo per generare un'altra chiave per questa chat")

    pubblica, privata = genera_chiavi()
    if not pubblica or not privata:
        raise HTTPException(status_code=500, detail="Impossibile generare le chiavi age")

    chiave_nuova = {
        "pubblica": pubblica,
        "privata": privata,
        "inizio": time.time(),
    }

    chiavi_lista = []
    if chiave_corrente_chat and chiave_corrente_chat.get('pubblica'):
        chiave_corrente_chat['fine'] = time.time() - 1
        chiavi_lista.append(chiave_corrente_chat)
    
    chiavi_lista.extend(chat_data.get('chiavi', []))
    
    data['data']['chats'][chat_id_hash] = {
        'chiave': chiave_nuova,
        'chiavi': chiavi_lista
    }

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    
    data_to_save = data['data'].copy()
    if 'masterkey' in data_to_save:
        del data_to_save['masterkey']
        
    vault_cifrato = cifra_vault(data_to_save, data['data']['masterkey'])
    set_user_vault(username, vault_cifrato)

    message_payload = {
        "cif": "in",
        "public": pubblica
    }
    
    try:
        await client.send_message(chat_id, json.dumps(message_payload))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
    
    return {"status": "ok", "public": pubblica}
