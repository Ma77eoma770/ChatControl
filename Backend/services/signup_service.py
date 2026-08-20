import sqlite3
import secrets
import hashlib
import time

from fastapi import Response, HTTPException
from cryptography.fernet import Fernet
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from database.sqlite import get_connection
from core.config import pepper, secret_key
from services.crypto_service import deriva_master_key, cifra_vault
from services.auth_service import login_cache
from services.realtime_service import register_telethon_handlers
from services.user_service import check_username_unicity

cipher = Fernet(secret_key.decode())
signup_cache = {}

def _build_and_store_vault(temp_data: dict, session_str: str, response: Response, client: TelegramClient, password_2fa: str | None = None):
    """
    Funzione di utilità per costruire il Master Vault (che conterrà API keys, Masterkey derivata e sessione Telethon) 
    e salvarlo cifrato simmetricamente nel Database SQLite alla conclusione con esito positivo del signup.
    """
    masterkey_str = temp_data['masterkey_derived'].decode() if isinstance(temp_data['masterkey_derived'], bytes) else temp_data['masterkey_derived']
    
    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "session": session_str
    }
    
    # Cifra l'intero dizionario JSON col masterkey in modo che diventi un BLOB opaco non intellegibile a DB
    vault_cifrato = cifra_vault(da_cifrare, temp_data['masterkey_derived'])

    # Re-inietta la masterkey nella copia RAM per le future operazioni
    da_cifrare["masterkey"] = masterkey_str

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_cifrato),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    response.delete_cookie("signup_session")

    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()

    login_cache[temp_id] = {
        "data": da_cifrare,
        "time": time.time(),
        "client": client
    }
    register_telethon_handlers(client, temp_id, temp_id_encrypted)

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )

async def create_user_logic(api_id: str, api_hash: str, phone: str, username_not_cyphered: str, password: str, response: Response):
    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    
    try:
        sent_code = await client.send_code_request(phone)
    except Exception as e:
        print(f"ERRORE TELEGRAM: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Errore Telegram: {str(e)}")
        
    temp_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    username = hashlib.sha256(pepper.encode() + username_not_cyphered.encode()).hexdigest()

    check_username_unicity(username)

    global signup_cache
    signup_cache[temp_id] = {
        "client": client,
        "phone": phone,
        "phone_code_hash": sent_code.phone_code_hash,
        "salt": salt,
        "masterkey_derived": deriva_master_key(password, salt),
        "api_id": api_id,
        "api_hash": api_hash,
        "username": username,
        "username_not_cyphered": username_not_cyphered
    }
    
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    response.set_cookie(
        key="signup_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=300,
    )
    
    return {"status": "SMS inviato"}

async def sign_up_verify_logic(sms_code: str, signup_session: str, response: Response):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
    
    client = temp_data['client']
    try: 
        await client.sign_in(temp_data['phone'], sms_code, phone_code_hash=temp_data['phone_code_hash'])
        session_str = client.session.save()
    except SessionPasswordNeededError:
        return {"status": "need_2fa_password"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Errore durante la verifica: {str(e)}")
    
    _build_and_store_vault(temp_data, session_str, response, client, password_2fa=None)
    return {"status": "Account creato!"}

async def sign_up_verify_password_logic(password: str, signup_session: str, response: Response):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")

    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
        
    client = temp_data['client']
    try: 
        await client.sign_in(password=password)
        session_str = client.session.save()
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    _build_and_store_vault(temp_data, session_str, response, client, password_2fa=password)
    return {"status": "Account creato!"}
