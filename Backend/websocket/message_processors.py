import json
import base64
import traceback
import hashlib
import io
from core.config import pepper
from services.auth_service import get_user_data_by_temp_id
from services.telegram_service import is_group_chat_id
from services.crypto_service import cifra_vault

from core.double_ratchet import generate_dh, dh, ratchet_init_bob, ratchet_init_alice
from services.double_ratchet_service import save_ratchet_state, load_ratchet_state, envelope_decrypt

def _hide_msg(message_data, msg):
    message_data['text'] = None
    message_data['chiave'] = msg
    message_data['is_system'] = True
    message_data['is_json'] = False
    if 'json' in message_data: del message_data['json']
    return message_data

async def _process_key_exchange(temp_id, event, message_data, parsed):
    cif_type = parsed.get("cif")
    pubblica_b64 = parsed.get("pub")
    
    if not pubblica_b64: return message_data
    
    user_data = get_user_data_by_temp_id(temp_id)
    if not user_data: return message_data
    
    masterkey = user_data['data']['masterkey']
    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_hash = hashlib.sha256(pepper.encode() + str(event.chat_id).encode()).hexdigest()
    is_group = is_group_chat_id(event.chat_id)
    
    my_id = message_data.get('my_id')
    is_mine = (my_id and message_data.get('sender_id') == my_id)

    if cif_type == "dr_init":
        if is_mine: return _hide_msg(message_data, "Double Ratchet Init (Inviato)")
            
        alice_ek_pub = base64.b64decode(pubblica_b64)
        bk_priv, bk_pub = generate_dh()
        sk = dh(bk_priv, alice_ek_pub)
        
        bob_state = ratchet_init_bob(sk, bk_priv, bk_pub, alice_ek_pub)
        save_ratchet_state(username, is_group, chat_id_hash, masterkey, bob_state)
        
        ack_payload = {"cif": "dr_ack", "pub": base64.b64encode(bk_pub).decode('utf-8')}
        client = user_data.get('client')
        if client:
            await client.send_message(event.chat_id, json.dumps(ack_payload))
            
    elif cif_type == "dr_ack":
        if is_mine: return _hide_msg(message_data, "Double Ratchet Ack (Inviato)")
            
        bob_bk_pub = base64.b64decode(pubblica_b64)
        chat_data = user_data['data'].get('chats', {}).get(chat_id_hash, {})
        pending_priv_b64 = chat_data.get('pending_dr_init_priv')
        if pending_priv_b64:
            ek_priv = base64.b64decode(pending_priv_b64)
            sk = dh(ek_priv, bob_bk_pub)
            ek_pub = chat_data.get('pending_dr_init_pub')
            if ek_pub:
                ek_pub_bytes = base64.b64decode(ek_pub)
                alice_state = ratchet_init_alice(sk, bob_bk_pub, ek_priv, ek_pub_bytes)
                save_ratchet_state(username, is_group, chat_id_hash, masterkey, alice_state)
            
            del chat_data['pending_dr_init_priv']
            if 'pending_dr_init_pub' in chat_data:
                del chat_data['pending_dr_init_pub']
            from services.user_service import set_user_vault
            data_copy = user_data['data'].copy()
            data_copy.pop('masterkey', None)
            vault_cifrato = cifra_vault(data_copy, masterkey)
            set_user_vault(username, vault_cifrato)

    return _hide_msg(message_data, "Handshake Double Ratchet elaborato")

async def _process_text_message(event, message_data, parsed, chat_keys, data):
    envelope = message_data['json'].get('envelope')
    if not envelope: return message_data
    
    user_data = get_user_data_by_temp_id(data.get('temp_id'))
    if not user_data: return message_data
    
    masterkey = user_data['data']['masterkey']
    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_hash = hashlib.sha256(pepper.encode() + str(event.chat_id).encode()).hexdigest()
    is_group = is_group_chat_id(event.chat_id)
    
    state = load_ratchet_state(username, is_group, chat_id_hash, masterkey)
    if not state:
        message_data['error'] = "Impossibile decifrare: Stato Ratchet mancante"
        return message_data
        
    try:
        text_decifrato, updated_state = envelope_decrypt(envelope, chat_id_hash, state)
        save_ratchet_state(username, is_group, chat_id_hash, masterkey, updated_state)
        
        dizionario = json.loads(text_decifrato.decode('utf-8'))
        message_data['text'] = dizionario.get('text', 'Decifrato ma testo vuoto')
        message_data['secure'] = True
    except Exception as e:
        traceback.print_exc()
        message_data['error'] = f"Errore decifratura Double Ratchet: {e}"

    if 'json' in message_data: del message_data['json']
    message_data['is_json'] = False
    return message_data

async def _process_document_payload(client, entity, event, message_data, parsed, chat_keys, data):
    return message_data

async def _process_encrypted_file(client, entity, event, message_data, parsed, chat_keys, data):
    return message_data
