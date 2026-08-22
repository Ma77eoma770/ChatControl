import json
import base64
import traceback
import hashlib
import io
from core.config import pepper
from services.auth_service import get_user_data_by_temp_id
from services.telegram_service import is_group_chat_id
from services.crypto_service import (
    is_valid_public_key, store_public_key_in_vault, decifra_payload,
    get_or_create_dr_session, save_dr_session_to_vault
)

async def _process_key_exchange(temp_id, event, message_data, parsed):
    """Gestisce l'evento in cui un altro utente ha inviato il payload JSON strutturato contenente la chiave criptografica."""
    my_id = message_data.get('my_id')
    # Ignora in UI il payload di scambio se l'ha originato lo stesso mittente locale
    if my_id and message_data.get('sender_id') == my_id:
        message_data['is_json'] = False
        message_data['text'] = None
        message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
        message_data['is_system'] = True
        return message_data
    
    pubblica = parsed.get("public")
    if pubblica and is_valid_public_key(pubblica):
        user_data = get_user_data_by_temp_id(temp_id)
        if user_data:
            # Salva in modo permanente la chiave appena ricevuta nel Vault del contatto/gruppo
            store_public_key_in_vault(
                user_data,
                event.chat_id,
                event.message.sender_id,
                pubblica,
                msg_date=getattr(message_data, "date", None),
                is_group=is_group_chat_id(event.chat_id),
                group_title=getattr(event.chat, "title", "Gruppo")
            )
    message_data['text'] = None
    message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
    message_data['is_system'] = True
    return message_data

async def _process_text_message(event, message_data, parsed, chat_keys, data):
    """Gestisce la ricezione di payload testuale cifrato (via MTProto)."""
    text_encrypted = message_data['json'].get('text')
    self_text_encrypted = message_data['json'].get('self_text')
    recip_text_encrypted = message_data['json'].get('recip_text')
    id_message_encrypted = message_data['json'].get('id')
    timestamp = message_data.get('date')

    # Usa la chiave privata corrente (nessuna retroattività)
    priv = chat_keys.get('chiave', {}).get('privata')
    candidate_privates = [priv] if priv else []

    is_out = message_data.get('out') or getattr(event.message, 'out', False)

    text_decifrato = None
    if is_out and self_text_encrypted:
        text_decifrato = decifra_payload(self_text_encrypted, candidate_privates)

    if not text_decifrato and not is_out:
        dr_session = None
        vault_deciphered = None
        chat_id = getattr(event, 'chat_id', None)
        if chat_id and not is_group_chat_id(chat_id):
            dr_session, vault_deciphered = get_or_create_dr_session(data, chat_id, is_initiator=False)

        # Tenta la decifratura asimmetrica passando come input le stringhe in base64
        text_decifrato = decifra_payload(text_encrypted, candidate_privates, dr_session=dr_session)
        if text_decifrato and dr_session and chat_id:
            save_dr_session_to_vault(data, chat_id, dr_session, vault_deciphered)

        if not text_decifrato and recip_text_encrypted:
            text_decifrato = decifra_payload(recip_text_encrypted, candidate_privates)

    if not text_decifrato:
        text_decifrato = decifra_payload(text_encrypted, candidate_privates)
        if not text_decifrato and self_text_encrypted:
            text_decifrato = decifra_payload(self_text_encrypted, candidate_privates)

    if text_decifrato:
        text_decifrato = text_decifrato.decode() if isinstance(text_decifrato, bytes) else text_decifrato

    id_message_decifrato_caption = decifra_payload(id_message_encrypted, candidate_privates)
    if id_message_decifrato_caption:
        id_message_decifrato_caption = id_message_decifrato_caption.decode() if isinstance(id_message_decifrato_caption, bytes) else id_message_decifrato_caption

    if text_decifrato:
        try:
            dizionario = json.loads(text_decifrato)
            if dizionario.get('cif') == "on":
                tempo_decifrato = dizionario.get('timestamp')
                id_message_decifrato = dizionario.get('id')
                diff_seconds = None
                if timestamp and tempo_decifrato is not None:
                    try:
                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                    except (TypeError, ValueError):
                        diff_seconds = None

                target_id = id_message_decifrato_caption or id_message_decifrato
                if (diff_seconds is not None and diff_seconds > 120):
                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                elif id_message_decifrato_caption and id_message_decifrato_caption != id_message_decifrato:
                    message_data['error'] = "questo messaggio e' stato modificato"
                else:
                    message_data['text'] = dizionario['text']
                    message_data['secure'] = True
                    if target_id:
                        data['ids_'].add(target_id)
            elif dizionario.get('cif') == "dummy":
                message_data['is_dummy'] = True
                message_data['text'] = None
                message_data['secure'] = True
                return message_data
            else:
                message_data['error'] = "questo messaggio e' stato modificato"

        except Exception:
            traceback.print_exc()

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data

async def _process_document_payload(client, entity, event, message_data, parsed, chat_keys, data):
    message_id = message_data.get('id')
    if not message_id:
        message_data['error'] = "nessun message id presente"
        return message_data

    full_message = await client.get_messages(entity, ids=message_id)
    if not full_message or not full_message.media or not full_message.document:
        message_data['error'] = "il messaggio dovrebbe contenere un documento, ma non e' presente"
        return message_data

    timestamp = message_data.get('date')
    priv = chat_keys.get('chiave', {}).get('privata')
    candidate_privates = [priv] if priv else []

    from services.crypto_service import decifra_payload_stream
    decrypted_stream = decifra_payload_stream(client.iter_download(full_message), candidate_privates)
   
    async def _read_exact(iterator, n: int, buffer: bytearray):
        while len(buffer) < n:
            try:
                chunk = await iterator.__anext__()
                if not chunk: break
                buffer.extend(chunk)
            except StopAsyncIteration:
                break
        if len(buffer) < n: return None
        res = bytes(buffer[:n])
        del buffer[:n]
        return res

    buffer = bytearray()
    try:
        metadata_size_bytes = await _read_exact(decrypted_stream, 4, buffer)
        if metadata_size_bytes:
            metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')
            inner_metadata_bytes = await _read_exact(decrypted_stream, metadata_size, buffer)
            
            if inner_metadata_bytes:
                try:
                    inner_metadata_str = inner_metadata_bytes.decode('utf-8')
                    inner_metadata = json.loads(inner_metadata_str)
                except Exception:
                    inner_metadata = None

                if inner_metadata and inner_metadata.get('cif') == 'message':
                    tempo_decifrato = inner_metadata.get('timestamp')
                    id_message_decifrato = inner_metadata.get('id')
                    diff_seconds = None
                    if timestamp and tempo_decifrato is not None:
                        try:
                            diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                        except (TypeError, ValueError):
                            diff_seconds = None

                    if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato in data['ids_']):
                        message_data['error'] = "questo messaggio e' frutto di un replay attack"
                    else:
                        message_bytes = bytearray(buffer)
                        async for chunk in decrypted_stream:
                            message_bytes.extend(chunk)
                            
                        message_data['text'] = message_bytes.decode('utf-8', errors='replace')
                        data['ids_'].add(id_message_decifrato)
                        message_data['secure'] = True
                        message_data['file'] = False
                        
                        message_data.pop('media_type', None)
                        message_data.pop('filename', None)
                        message_data.pop('mime', None)
                        message_data.pop('size', None)
    except Exception:
        pass

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data

async def _process_encrypted_file(client, entity, event, message_data, parsed, chat_keys, data):
    message_id = message_data.get('id')
    
    if message_id:
        full_message = await client.get_messages(entity, ids=message_id)
        if full_message and full_message.media:
            file_bytes = io.BytesIO()
            max_bytes = 64 * 1024
            downloaded = 0
            async for chunk in client.iter_download(full_message, offset=0, limit=max_bytes):
                if not chunk:
                    break
                file_bytes.write(chunk)
                downloaded += len(chunk)
                if downloaded >= max_bytes:
                    break
            file_bytes.seek(0)
            file_head_bytes = file_bytes.getvalue()
            message_data['file_head'] = base64.b64encode(file_head_bytes).decode()
            message_data['file_head_size'] = len(file_head_bytes)

    timestamp = message_data.get('date')
    priv = chat_keys.get('chiave', {}).get('privata')
    candidate_privates = [priv] if priv else []

    text_decifrato = None
    if message_id and 'file_head_size' in message_data:
        from services.crypto_service import estrai_metadata_da_stream
        async def _mem_stream():
            yield file_head_bytes
            
        text_decifrato = await estrai_metadata_da_stream(_mem_stream(), candidate_privates)

    if text_decifrato:
        try:
            dizionario = json.loads(text_decifrato)
            if dizionario.get('cif') == "file":
                tempo_decifrato = dizionario.get('timestamp')
                id_message_decifrato = dizionario.get('id')
                diff_seconds = None
                if timestamp and tempo_decifrato is not None:
                    try:
                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                    except (TypeError, ValueError):
                        diff_seconds = None
                
                allowed_seconds = 30
                file_size = dizionario.get('size')
                if file_size is not None:
                    try:
                        file_size = float(file_size)
                        allowed_seconds = max(30, file_size / (32 * 1024))
                    except (TypeError, ValueError):
                        pass

                if (diff_seconds is not None and diff_seconds > allowed_seconds) or (id_message_decifrato in data['ids_']):
                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                else:
                    message_data['file'] = True
                    message_data['filename'] = dizionario.get('filename')
                    message_data['text'] = dizionario.get('text')
                    message_data['mime'] = dizionario.get('mime')
                    message_data['size'] = dizionario.get('size')
                    message_data['secure'] = True
                    data['ids_'].add(id_message_decifrato)
            else:
                message_data['error'] = "questo messaggio e' stato modificato"
        except Exception:
            traceback.print_exc()

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data
