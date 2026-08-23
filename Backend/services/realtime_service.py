import hashlib
import sqlite3
import json
from telethon import events, utils
from telethon.tl.types import (
    PeerChannel,
    UpdateDeleteChannelMessages,
    UpdateDeleteMessages,
)
from core.config import pepper
from database.sqlite import get_connection
from services.crypto_service import cifra_vault, decifra_vault
from services.auth_service import get_user_data_by_temp_id, is_logged_in
from services.telegram_service import is_group_chat_id, set_media

from websocket.connection_manager import (
    connect_socket, disconnect_socket, broadcast_event, 
    index_messages, drop_message_ids, resolve_chat_id_for_deleted
)
from websocket.message_processors import (
    _process_key_exchange, _process_text_message,
    _process_document_payload, _process_encrypted_file
)
from services.dpi_service import revert_covert_mimicry


async def _remove_user_from_vault(temp_id: str, chat_id: int, user_id: int | None):
    """Rimuove l'utente dal vault segreto del gruppo se esce o viene rimosso, aggiornando il DB."""
    user_data = get_user_data_by_temp_id(temp_id)
    if not user_data:
        return
    if user_id is not None and not is_group_chat_id(chat_id):
        if str(user_id) != str(chat_id):
            return
    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    is_group = is_group_chat_id(chat_id)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    return
                vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
                partecipanti = vault_deciphered.get('partecipanti')
                if not partecipanti or str(user_id) not in partecipanti:
                    return
                del partecipanti[str(user_id)]
                vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                    (vault_cifrato, username, chat_id_cif)
                )
                conn.commit()
            else:
                cursor.execute(
                    """DELETE FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                conn.commit()
    except sqlite3.Error as error:
        print(f"ERROR remove_user_from_vault: {error}")

def _serialize_message(msg):
    """Converte l'oggetto Entity Messaggio nativo di Telethon in un dizionario Python piatto facile da spedire su WebSocket."""
    message_data = {
        "id": msg.id,
        "chat_id": msg.chat_id,
        "text": msg.message or "",
        "date": msg.date if msg.date else None,
        "sender_id": msg.sender_id,
        "out": msg.out,
        "reply_to": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
    }
    if msg.media:
        set_media(msg, message_data)
    return message_data


def register_telethon_handlers(client, temp_id: str, login_session: str):
    """
    Registra gli handler (listener callback) necessari sull'istanza Telethon per intercettare gli update
    push da Telegram (NewMessage, MessageEdited, MessageDeleted) e instradarli istantaneamente ai WebSocket web client.
    """
    if getattr(client, "_cc_handlers_added", False):
        return

    async def handle_new_message(event):
        try:
            entity = await client.get_entity(event.chat_id)
        except Exception:
            return 
            
        temp_id_logged, data = is_logged_in(login_session, False)
        me = await client.get_me()
        my_id = me.id if me else None
        
        message_data = _serialize_message(event.message)
        message_data['my_id'] = my_id

        sender = await event.message.get_sender()
        message_data['sender_username'] = getattr(sender, 'username', None) if sender else None
        chat_id_cif = hashlib.sha256(pepper.encode() + str(event.chat_id).encode()).hexdigest()

        if not event.chat_id:
            return
            
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
            
        if event.message and not getattr(event.message, "out", False):
            text = event.message.message or ""
            parsed = None
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    parsed = revert_covert_mimicry(parsed)
                    message_data['json'] = parsed
                    message_data['is_json'] = True
                else:
                    message_data['is_json'] = False
            except Exception:
                message_data['is_json'] = False

            if message_data['is_json']:
                cif_flag = parsed.get("CIF") or parsed.get("cif")
                chat_keys = data['data'].get('chats', {}).get(chat_id_cif, {})

                if cif_flag == "in":
                    message_data = await _process_key_exchange(temp_id, event, message_data, parsed)
                elif cif_flag == "on":
                    message_data = await _process_text_message(event, message_data, parsed, chat_keys, data)
                elif cif_flag == "message":
                    message_data = await _process_document_payload(client, entity, event, message_data, parsed, chat_keys, data)
                elif cif_flag == "file":
                    message_data = await _process_encrypted_file(client, entity, event, message_data, parsed, chat_keys, data)


        payload = {
            "event_type": "new",
            "chat_id": event.chat_id,
            "message": message_data,
        }
        await broadcast_event(temp_id, event.chat_id, payload)


    async def handle_edited_message(event):
        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        message_data = _serialize_message(event.message)
        payload = {
            "event_type": "edited",
            "chat_id": event.chat_id,
            "message": message_data,
        }
        await broadcast_event(temp_id, event.chat_id, payload)

    async def handle_deleted_message(event):
        message_ids = list(event.deleted_ids or [])
        if not message_ids:
            return
        chat_id = getattr(event, "chat_id", None)
        if not chat_id:
            peer = getattr(event, "peer_id", None)
            if peer is not None:
                try:
                    chat_id = utils.get_peer_id(peer)
                except Exception:
                    chat_id = None
        if not chat_id:
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
        if not chat_id:
            return
        await drop_message_ids(temp_id, chat_id, message_ids)
        
        payload = {
            "event_type": "deleted",
            "chat_id": chat_id,
            "message_ids": message_ids,
        }
        await broadcast_event(temp_id, chat_id, payload)

    async def handle_raw_update(event):
        update = getattr(event, "update", event)
        if isinstance(update, UpdateDeleteChannelMessages):
            chat_id = utils.get_peer_id(PeerChannel(update.channel_id))
            message_ids = list(update.messages or [])
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)
        elif isinstance(update, UpdateDeleteMessages):
            message_ids = list(update.messages or [])
            if not message_ids:
                return
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
            if not chat_id:
                return
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)

    async def handle_chat_action(event):
        if not event.chat_id:
            return
        if not (getattr(event, "user_left", False) or getattr(event, "user_kicked", False)):
            return
        user_ids = []
        if getattr(event, "user_id", None):
            user_ids.append(event.user_id)
        elif getattr(event, "user_ids", None):
            user_ids.extend(list(event.user_ids))

        for uid in user_ids:
            await _remove_user_from_vault(temp_id, event.chat_id, uid)

    client.add_event_handler(handle_new_message, events.NewMessage())
    client.add_event_handler(handle_edited_message, events.MessageEdited())
    client.add_event_handler(handle_deleted_message, events.MessageDeleted())
    client.add_event_handler(handle_raw_update, events.Raw())
    client.add_event_handler(handle_chat_action, events.ChatAction())
    client._cc_handlers_added = True

