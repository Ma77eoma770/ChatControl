import sqlite3
import json
import base64
import os
import io
import mimetypes
from datetime import datetime, timedelta
import hashlib
import traceback
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from core.config import pepper, enable_dpi_obfuscation
from services.crypto_service import (
    cifra_vault, is_valid_public_key, store_public_key_in_vault,
    decifra_payload, get_or_create_dr_session, save_dr_session_to_vault
)
from services.auth_service import is_logged_in
from services.telegram_service import is_group_chat_id, set_media
from services.realtime_service import index_messages
from database.sqlite import get_connection
from services.dpi_service import revert_covert_mimicry, PAD_MAGIC, unpad_payload_from_bucket
from services.user_service import get_gruppo_vault, get_chat_vault
from telethon.tl.types import (
    MessageService, MessageActionChatCreate, MessageActionChatDeleteUser, 
    MessageActionChatAddUser, MessageActionPinMessage
)

async def get_chats_logic(login_session: str, offset_date: str = None):
    _, data = is_logged_in(login_session, False)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    dt = datetime.fromisoformat(offset_date) if offset_date else None
    chats = []

    async for dialog in client.iter_dialogs(limit=20, offset_date=dt):
        chat_info = {
            'id': dialog.id,
            'name': dialog.name if dialog.name else "Account Eliminato",
            'unread_count': dialog.unread_count,
            'is_user': dialog.is_user,
            'is_group': dialog.is_group,
            'is_channel': dialog.is_channel,
        }
        
        if dialog.message:
            chat_info['last_message'] = {
                'text': dialog.message.text or '',
                'date': dialog.date if dialog.message else None,
                'sender_id': dialog.message.sender_id
            }
        
        chats.append(chat_info)
        
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT contatto_id FROM contatti WHERE proprietario = ?
                   UNION
                   SELECT gruppo_id FROM contatti_gruppo WHERE proprietario = ?""",
                (username, username)
            )
            risultati = cursor.fetchall()
            encrypted_ids = {row[0] for row in risultati}
            chats_data = data.get('data', {}).get('chats', {})

            for chat in chats:
                chat_id_hash = hashlib.sha256(pepper.encode() + str(chat['id']).encode()).hexdigest()
                has_remote_key = chat_id_hash in encrypted_ids
                chat_data = chats_data.get(chat_id_hash, {})
                has_own_key = bool(chat_data.get('chiave', {}).get('pubblica'))
                chat['cyphered'] = has_remote_key or has_own_key
                
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    return {"chats": chats}

async def _get_system_message(msg: MessageService, client) -> str:
    action = msg.action
    if isinstance(action, MessageActionChatCreate):
        return f"Gruppo creato: {action.title}"
    elif isinstance(action, MessageActionChatDeleteUser):
        left_user = getattr(action, 'user_id', None)
        left_user_name = None
        if left_user:
            try:
                left_user_entity = await client.get_entity(left_user)
                left_user_name = getattr(left_user_entity, 'username', None) or getattr(left_user_entity, 'first_name', None) or str(left_user)
            except Exception:
                left_user_name = str(left_user)
        return f"{left_user_name} ha lasciato il gruppo" if left_user_name else "Un utente ha lasciato il gruppo"
    elif isinstance(action, MessageActionChatAddUser):
        added_users = getattr(action, 'users', None)
        if added_users and isinstance(added_users, list):
            names = []
            for user_id in added_users:
                try:
                    user_entity = await client.get_entity(user_id)
                    name = getattr(user_entity, 'username', None) or getattr(user_entity, 'first_name', None) or str(user_id)
                except Exception:
                    name = str(user_id)
                names.append(name)
            return f"{', '.join(names)} è entrato nel gruppo"
        return "Un utente è entrato nel gruppo"
    elif isinstance(action, MessageActionPinMessage):
        return f"Un messaggio è stato pinnato nella chat(id: {msg.id})"
    return "Notifica di sistema"

def _calculate_time_window(messages: list) -> tuple[datetime | None, datetime | None]:
    window_start, window_end = None, None
    for m in messages:
        dt = m.get('date')
        if dt and (window_end is None or dt < window_end):
            window_end = dt

    for message in messages:
        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = revert_covert_mimicry(parsed)
                message['json'] = parsed
                message['is_json'] = True
            else:
                message['is_json'] = False
        except Exception:
            message['is_json'] = False
        
        if message['is_json'] and window_end is not None:
            cif_flag = message['json'].get('CIF') or message['json'].get('cif')
            if cif_flag in ("file", "message") and message.get('file') and message.get('size') is not None:
                try:
                    size_bytes = float(message.get('size') or 0)
                except (TypeError, ValueError):
                    size_bytes = 0

                if size_bytes > 0 and message.get('date'):
                    download_time = size_bytes / (32 * 1024)
                    candidate_start = message['date'] - timedelta(seconds=download_time)
                    if window_start is None or candidate_start < window_start:
                        window_start = candidate_start
            if cif_flag == "on" and (window_start is None or message['date'] < window_start):
                window_start = message['date']

    if window_end is not None:
        if window_start is None:
            window_start = window_end - timedelta(seconds=10)
        min_delta = timedelta(seconds=10)
        if window_end - window_start < min_delta:
            window_start = window_end - min_delta
            
    return window_start, window_end

def _populate_decrypted_ids(messages_in_window: list, data: dict, chat_keys: dict):
    for message in messages_in_window:
        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                continue
            parsed = revert_covert_mimicry(parsed)
            cif_flag = parsed.get('CIF') or parsed.get('cif')
            if cif_flag not in ("on", "file", "message"):
                continue
            id_message = parsed.get('id')
            if not id_message:
                continue

            priv = chat_keys.get('chiave', {}).get('privata')
            candidate_privates = [priv] if priv else []
            if not candidate_privates:
                continue

            dec_id = decifra_payload(id_message, candidate_privates)
            if dec_id:
                dec_id_str = dec_id.decode('utf-8') if isinstance(dec_id, bytes) else dec_id
                data['ids_'].add(dec_id_str)
        except Exception:
            pass

def _handle_key_exchange(message: dict, entity, chat_id: int, data: dict, my_id: int):
    if my_id and message.get('sender_id') == my_id:
        message.update({
            'is_json': False, 'text': None, 
            'chiave': "Questo messaggio e' uno scambio di chiave", 'is_system': True
        })
        return

    pubblic = message['json'].get('public')
    if pubblic is None or not is_valid_public_key(pubblic):
        return

    store_public_key_in_vault(
        data, chat_id, message.get('sender_id'), pubblic,
        msg_date=message.get('date'),
        is_group=is_group_chat_id(chat_id),
        group_title=getattr(entity, 'title', 'Gruppo')
    )
    message.update({
        'text': None, 'chiave': "Questo messaggio e' uno scambio di chiave", 'is_system': True
    })

def _handle_encrypted_text(message: dict, data: dict, chat_keys: dict, chat_id: int | None = None):
    text_enc = message['json'].get('text')
    self_text_enc = message['json'].get('self_text')
    recip_text_enc = message['json'].get('recip_text')
    timestamp = message.get('date')
    id_enc = message['json'].get('id')

    from services.crypto_service import get_all_user_private_keys
    priv = chat_keys.get('chiave', {}).get('privata')
    candidates = [priv] if priv else []
    for pk in get_all_user_private_keys(data):
        if pk not in candidates:
            candidates.append(pk)

    is_outgoing = message.get('out', False)

    text_dec = None
    if is_outgoing and self_text_enc:
        text_dec = decifra_payload(self_text_enc, candidates)

    if not text_dec and not is_outgoing:
        dr_session = None
        vault_deciphered = None
        if chat_id and not is_group_chat_id(chat_id):
            dr_session, vault_deciphered = get_or_create_dr_session(data, chat_id, is_initiator=False)

        text_dec = decifra_payload(text_enc, candidates, dr_session=dr_session)
        if text_dec and dr_session and chat_id:
            save_dr_session_to_vault(data, chat_id, dr_session, vault_deciphered)

        if not text_dec and recip_text_enc:
            text_dec = decifra_payload(recip_text_enc, candidates)

    if not text_dec:
        text_dec = decifra_payload(text_enc, candidates)
        if not text_dec and self_text_enc:
            text_dec = decifra_payload(self_text_enc, candidates)

    if text_dec:
        text_dec = text_dec.decode('utf-8') if isinstance(text_dec, bytes) else text_dec

    id_dec_cap = decifra_payload(id_enc, candidates)
    if id_dec_cap:
        id_dec_cap = id_dec_cap.decode('utf-8') if isinstance(id_dec_cap, bytes) else id_dec_cap

    if text_dec:
        try:
            diz = json.loads(text_dec)
            if diz.get('cif') == "on":
                tempo_dec = diz.get('timestamp')
                id_dec = diz.get('id')
                diff_sec = abs(timestamp.timestamp() - float(tempo_dec)) if (timestamp and tempo_dec is not None) else None
                
                target_id = id_dec_cap or id_dec
                if (diff_sec is not None and diff_sec > 120):
                    message['error'] = "questo messaggio e' frutto di un replay attack"
                elif id_dec_cap and id_dec_cap != id_dec:
                    message['error'] = "questo messaggio e' stato modificato"
                else:
                    message['text'] = diz['text']
                    message['secure'] = True
                    if target_id:
                        data['ids_'].add(target_id)
            else:
                message['error'] = "questo messaggio e' stato modificato"
        except Exception:
            traceback.print_exc()

    message['is_json'] = False
    message.pop('json', None)

async def _handle_encrypted_file(message: dict, client, entity, data: dict, chat_keys: dict):
    msg_id = message.get('id')
    file_head_bytes = None

    if msg_id:
        full_message = await client.get_messages(entity, ids=msg_id)
        if full_message and full_message.media:
            file_bytes = io.BytesIO()
            max_bytes = 64 * 1024
            downloaded = 0
            async for chunk in client.iter_download(full_message, offset=0, limit=max_bytes):
                if not chunk: break
                file_bytes.write(chunk)
                downloaded += len(chunk)
                if downloaded >= max_bytes: break
            
            file_head_bytes = file_bytes.getvalue()
            message['file_head'] = base64.b64encode(file_head_bytes).decode()
            message['file_head_size'] = len(file_head_bytes)

    timestamp = message.get('date')
    priv = chat_keys.get('chiave', {}).get('privata')
    candidates = [priv] if priv else []

    text_dec = None
    if file_head_bytes:
        from services.crypto_service import estrai_metadata_da_stream
        async def _mem_stream():
            yield file_head_bytes
            
        text_dec = await estrai_metadata_da_stream(_mem_stream(), candidates)


    if text_dec:
        try:
            diz = json.loads(text_dec)
            if diz.get('cif') == "file":
                tempo_dec = diz.get('timestamp')
                id_dec = diz.get('id')
                diff_sec = abs(timestamp.timestamp() - float(tempo_dec)) if (timestamp and tempo_dec is not None) else None

                allowed_seconds = 30
                file_size = diz.get('size')
                if file_size is not None:
                    try:
                        allowed_seconds = max(30, float(file_size) / (32 * 1024))
                    except (TypeError, ValueError):
                        pass

                if (diff_sec is not None and diff_sec > allowed_seconds) or (id_dec in data['ids_']):
                    message['error'] = "questo messaggio e' frutto di un replay attack"
                else:
                    message.update({
                        'file': True, 'filename': diz.get('filename'),
                        'text': diz.get('text'), 'mime': diz.get('mime'),
                        'size': diz.get('size'), 'secure': True
                    })
                    data['ids_'].add(id_dec)
            else:
                message['error'] = "questo messaggio e' stato modificato"
        except Exception:
            traceback.print_exc()

    message['is_json'] = False
    message.pop('json', None)

async def _handle_encrypted_document_payload(message: dict, client, entity, data: dict, chat_keys: dict):
    msg_id = message.get('id')
    if not msg_id: return

    full_message = await client.get_messages(entity, ids=msg_id)
    if not full_message or not full_message.media or not full_message.document:
        return

    timestamp = message.get('date')
    priv = chat_keys.get('chiave', {}).get('privata')
    candidates = [priv] if priv else []

    from services.crypto_service import decifra_payload_stream

    decrypted_stream = decifra_payload_stream(client.iter_download(full_message), candidates)
    
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
        first4 = await _read_exact(decrypted_stream, 4, buffer)
        if first4:
            message_content_bytes = None
            if first4 == PAD_MAGIC:
                orig_len_bytes = await _read_exact(decrypted_stream, 4, buffer)
                orig_len = int.from_bytes(orig_len_bytes, byteorder='big')
                metadata_size_bytes = await _read_exact(decrypted_stream, 4, buffer)
                metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')
                inner_metadata_bytes = await _read_exact(decrypted_stream, metadata_size, buffer)
                content_len = orig_len - 4 - metadata_size
                if content_len >= 0:
                    message_content_bytes = await _read_exact(decrypted_stream, content_len, buffer)
            else:
                metadata_size = int.from_bytes(first4, byteorder='big')
                inner_metadata_bytes = await _read_exact(decrypted_stream, metadata_size, buffer)

            if inner_metadata_bytes:
                try:
                    inner_metadata = json.loads(inner_metadata_bytes.decode('utf-8'))
                except Exception:
                    inner_metadata = None

                if inner_metadata and inner_metadata.get('cif') == 'message':
                    tempo_dec = inner_metadata.get('timestamp')
                    id_dec = inner_metadata.get('id')
                    diff_sec = abs(timestamp.timestamp() - float(tempo_dec)) if (timestamp and tempo_dec is not None) else None

                    if (diff_sec is not None and diff_sec > 10) or (id_dec in data['ids_']):
                        message['error'] = "questo messaggio e' frutto di un replay attack"
                    else:
                        if message_content_bytes is None:
                            content_buf = bytearray(buffer)
                            async for chunk in decrypted_stream:
                                content_buf.extend(chunk)
                            message_content_bytes = bytes(content_buf)

                        message['text'] = message_content_bytes.decode('utf-8', errors='replace')
                        data['ids_'].add(id_dec)
                        message.update({'secure': True, 'file': False})
                        for key in ['media_type', 'filename', 'mime', 'size']:
                            message.pop(key, None)
    except Exception:
        pass

    message['is_json'] = False
    message.pop('json', None)


async def get_chat_messages_logic(chat_id: int, limit: int, start: int, login_session: str):
    temp_id, data = is_logged_in(login_session, False)
    if data.get('active_chat_id') != chat_id:
        data['ids_'] = set()
        data['active_chat_id'] = chat_id
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    if "ids_" not in data:
        data['ids_'] = set()

    client = data['client']
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    messages = []
    add_offset = start if start and start > 0 else 0
    iter_kwargs = {"limit": limit}
    if add_offset:
        iter_kwargs["add_offset"] = add_offset
        
    async for msg in client.iter_messages(entity, **iter_kwargs):
        sender = await msg.get_sender()
        system_message = await _get_system_message(msg, client) if isinstance(msg, MessageService) else None

        message_data = {
            'id': msg.id,
            'chat_id': chat_id,
            'text': msg.message or '',
            'date': msg.date if msg.date else None,
            'sender_id': msg.sender_id,
            'sender_username': getattr(sender, 'username', None) if sender else None,
            'out': msg.out,
            'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
            'system_type': system_message,
        }
        
        if msg.media:
            set_media(msg, message_data)
        
        messages.append(message_data)

    await index_messages(temp_id, chat_id, [m.get("id") for m in messages if m.get("id") is not None])

    window_start, window_end = _calculate_time_window(messages)
    
    messages_in_window = []
    if window_start is not None and window_end is not None and window_start < window_end:
        async for msg in client.iter_messages(entity, offset_date=window_end):
            if not msg.date or msg.date >= window_end: continue
            if msg.date < window_start: break

            sender = await msg.get_sender()
            message_data = {
                'id': msg.id, 'chat_id': chat_id, 'text': msg.message or '', 'date': msg.date if msg.date else None,
                'sender_id': msg.sender_id, 'sender_username': getattr(sender, 'username', None) if sender else None,
                'out': msg.out, 'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
            }
            if msg.media:
                set_media(msg, message_data)
            messages_in_window.append(message_data)

    chats_data = data['data'].get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    
    _populate_decrypted_ids(messages_in_window, data, chat_keys)

    for message in messages:
        if message['system_type']:
            continue

        cif_flag = None
        if message.get('is_json'):
            cif_flag = message.get('json', {}).get('CIF') or message.get('json', {}).get('cif')
        
        if cif_flag == "in":
            _handle_key_exchange(message, entity, chat_id, data, my_id)
        elif cif_flag == "on":
             _handle_encrypted_text(message, data, chat_keys, chat_id)
        elif cif_flag == "file":
            await _handle_encrypted_file(message, client, entity, data, chat_keys)
        elif cif_flag == "message":
            await _handle_encrypted_document_payload(message, client, entity, data, chat_keys)

    messages.reverse() 
    return {"chat_id": chat_id, "messages": messages}

async def get_init_messages_logic(chat_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    init_messages = []
    async for msg in client.iter_messages(entity, limit=None):
        if my_id and msg.sender_id == my_id:
            continue
        text = msg.message or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = revert_covert_mimicry(parsed)
                cif_flag = parsed.get('CIF') or parsed.get('cif')
                pubblic = parsed.get('public')
                if cif_flag == "in" and pubblic is not None and is_valid_public_key(pubblic):
                    init_messages.append({
                        'id': msg.id, 'date': msg.date, 'public_key': pubblic, 'sender_id': msg.sender_id
                    })
        except Exception:
            pass

    is_group = is_group_chat_id(chat_id)
    vault_deciphered = None
    insert_new_vault = False
    
    try:
        if is_group:
            insert_new_vault, vault_deciphered = get_gruppo_vault(username, chat_id, entity, data)
        else:
            insert_new_vault, vault_deciphered = await get_chat_vault(username, chat_id, client, data)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    vault_dirty = False
    if is_group:
        ids = set()
        async for user in client.iter_participants(chat_id):
            ids.add(str(user.id))
        if 'partecipanti' in vault_deciphered:
            stale_ids = [pid for pid in vault_deciphered['partecipanti'].keys() if pid not in ids]
            for pid in stale_ids:
                del vault_deciphered['partecipanti'][pid]
            if stale_ids:
                vault_dirty = True

    all_keys = []
    if is_group and 'partecipanti' in vault_deciphered:
        for participant_data in vault_deciphered['partecipanti'].values():
            current_key = participant_data.get('chiave', {})
            if current_key and current_key.get('chiave'):
                all_keys.append(current_key)
            if 'chiavi' in participant_data:
                all_keys.extend(participant_data['chiavi'])
    elif not is_group and 'chiavi' in vault_deciphered:
        all_keys.extend(vault_deciphered['chiavi'])

    existing_keys = {k['chiave'] for k in all_keys}
    keys_added = 0

    for init_msg in init_messages:
        pubblic = init_msg['public_key']
        if pubblic not in existing_keys:
            new_key_timestamp = init_msg['date'].timestamp()
            new_key = {'chiave': pubblic, 'inizio': new_key_timestamp, 'fine': None}
            
            if is_group:
                sender_id = str(init_msg['sender_id'])
                if sender_id not in vault_deciphered['partecipanti']:
                    vault_deciphered['partecipanti'][sender_id] = {'chiave': {}, 'chiavi': []}
                
                current_key = vault_deciphered['partecipanti'][sender_id].get('chiave', {})
                if current_key and current_key.get('chiave'):
                    current_key['fine'] = new_key_timestamp - 1
                    vault_deciphered['partecipanti'][sender_id].setdefault('chiavi', []).append(current_key)
                
                vault_deciphered['partecipanti'][sender_id]['chiave'] = new_key
            else:
                if vault_deciphered['chiavi']:
                    vault_deciphered['chiavi'][-1]['fine'] = new_key_timestamp - 1
                vault_deciphered['chiavi'].append(new_key)
            
            existing_keys.add(pubblic)
            keys_added += 1
            vault_dirty = True

    if vault_dirty:
        vault_cifrato = cifra_vault(vault_deciphered, data['data']['masterkey'])
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                if is_group:
                    if insert_new_vault:
                        cursor.execute("""INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""", (username, chat_id_cif, vault_cifrato))
                    else:
                        cursor.execute("""UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""", (vault_cifrato, username, chat_id_cif))
                else:
                    if insert_new_vault:
                        cursor.execute("""INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""", (username, chat_id_cif, vault_cifrato))
                    else:
                        cursor.execute("""UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""", (vault_cifrato, username, chat_id_cif))
                conn.commit()
        except sqlite3.Error as error:
            raise HTTPException(status_code=500, detail=str(error))

    return {
        "chat_id": chat_id,
        "init_messages_found": len(init_messages),
        "keys_added": keys_added,
        "total_keys": len(existing_keys)
    }

async def download_media_logic(chat_id: int, message_id: int, login_session: str):
    _, data = is_logged_in(login_session, False)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)
        
        if not message: raise HTTPException(status_code=404, detail="Messaggio non trovato")
        if not message.media: raise HTTPException(status_code=404, detail="Messaggio senza media")
        
        mime_type = 'application/octet-stream'
        if message.sticker: mime_type = message.sticker.mime_type or 'image/webp'
        elif message.gif: mime_type = message.gif.mime_type or 'video/mp4'
        elif message.photo: mime_type = 'image/jpeg'
        elif message.video: mime_type = message.video.mime_type or 'video/mp4'
        elif message.document: mime_type = message.document.mime_type or 'application/octet-stream'
        
        async def _stream_generator():
            async for chunk in client.iter_download(message):
                yield chunk

        return StreamingResponse(
            _stream_generator(), media_type=mime_type,
            headers={'Cache-Control': 'public, max-age=31536000', 'ETag': f'"{chat_id}-{message_id}"'}
        )
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")

async def download_encrypt_media_logic(chat_id: int, message_id: int, login_session: str):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)

        if not message: raise HTTPException(status_code=404, detail="Messaggio non trovato")
        if not message.media or not message.document: raise HTTPException(status_code=404, detail="Senza documento")

        filename = next((attr.file_name for attr in (message.document.attributes or []) if hasattr(attr, 'file_name')), None)
        if not filename or not filename.endswith('.dat'):
            raise HTTPException(status_code=400, detail="Documento non cifrato")

        caption_json = json.loads(message.message or "{}")
        if isinstance(caption_json, dict):
            caption_json = revert_covert_mimicry(caption_json)
        if caption_json.get('CIF', caption_json.get('cif')) != "file":
            raise HTTPException(status_code=400, detail="Caption non cifrata")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chat_keys = data['data'].get('chats', {}).get(chat_id_cif, {})
        priv = chat_keys.get('chiave', {}).get('privata')
        candidates = [priv] if priv else []
        if not candidates: raise HTTPException(status_code=400, detail="Nessuna chiave")

        from services.crypto_service import decifra_payload_stream
        from services.fast_telethon import download_file
        import tempfile
        import os
        
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".dat")
        os.close(tmp_fd)
        
        await download_file(client, message.media.document, tmp_path, message.document.size)
        
        async def file_chunk_generator():
            with open(tmp_path, "rb") as f:
                while chunk := f.read(512 * 1024):
                    yield chunk
                    
        decrypted_stream = decifra_payload_stream(file_chunk_generator(), candidates)
        
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
        metadata_size_bytes = await _read_exact(decrypted_stream, 4, buffer)
        if not metadata_size_bytes:
            if os.path.exists(tmp_path): os.remove(tmp_path)
            raise HTTPException(status_code=400, detail="Payload invalido o vuoto")
            
        metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')
        metadata_bytes = await _read_exact(decrypted_stream, metadata_size, buffer)
        
        if not metadata_bytes:
            if os.path.exists(tmp_path): os.remove(tmp_path)
            raise HTTPException(status_code=400, detail="Metadati incompleti")
            
        metadata = json.loads(metadata_bytes.decode('utf-8'))
        if metadata.get('cif') != 'file': 
            if os.path.exists(tmp_path): os.remove(tmp_path)
            raise HTTPException(status_code=400, detail="Metadata non cifrati o tipo errato")

        out_filename = os.path.basename(metadata.get('filename') or 'file.bin')
        mime_type = metadata.get('mime') or mimetypes.guess_type(out_filename)[0] or 'application/octet-stream'
        
        async def _file_stream_generator():
            try:
                if buffer:
                    yield bytes(buffer)
                async for chunk in decrypted_stream:
                    yield chunk
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                
        return StreamingResponse(
            _file_stream_generator(), media_type=mime_type,
            headers={'Content-Disposition': f'attachment; filename="{out_filename}"', 'Cache-Control': 'no-store'}
        )
            
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
