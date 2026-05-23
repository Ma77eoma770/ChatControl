from database.sqlite import get_connection
from fastapi import HTTPException
import sqlite3
from services.crypto_service import deriva_master_key, decifra_vault
import hashlib
from core.config import pepper

def get_user_informations(username: str, password: str) -> dict:
    """Recupera e decifra il master vault dell'utente dal DB dato username e password."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)
            # Estrae il DB salt (univoco per utente) per derivare correttamente la masterkey
            cursor.execute(
                "SELECT salt, vault FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is None:
                raise HTTPException(status_code=401)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    salt_db = risultati[0]
    # Rigenera la chiave AES (master_key) sfruttando l'Argon2 passata dal client al volo
    master_key = deriva_master_key(password, salt_db)

    try:
        # Decifra e de-serializza il blob restituendo il dizionario (master vault)
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return vault_decyphered, master_key

def set_user_vault(username: str, vault_cyphered: bytes) -> None:
    """Aggiorna il master vault cifrato di un utente nel DB."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utenti SET vault = ? WHERE username = ?",
                (vault_cyphered, username),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def check_username_unicity(username: str) -> None:
    """Verifica che lo username non esista già nel DB, altrimenti lancia eccezione."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is not None:
                raise HTTPException(status_code=400)
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def get_gruppo_vault(username: str, chat_id: str, entity, data: dict) -> tuple[bool, dict]:
    """Estrapola il sub-vault di un gruppo dal DB o ne inizializza uno nuovo."""
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT ratchet_vault FROM sessioni_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
            (username, chat_id_cif)
        )
        risultato = cursor.fetchone()
        
        if not risultato or not risultato[0]:
            vault_deciphered = {
                'gruppo_id': chat_id,
                'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                'partecipanti': {}
            }
            insert_new_vault = True
        else:
            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            insert_new_vault = False
            
    return insert_new_vault, vault_deciphered
                
async def get_chat_vault(username: str, chat_id: str, client, data: dict) -> tuple[bool, dict]:
    """Estrapola il sub-vault di una chat singola dal DB o ne inizializza uno nuovo."""
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT ratchet_vault FROM sessioni_ratchet WHERE proprietario = ? AND contatto_id = ?""",
            (username, chat_id_cif)
        )
        risultato = cursor.fetchone()
        
        if not risultato or not risultato[0]:
            sender = await client.get_entity(chat_id)
            vault_deciphered = {
                'user_id': chat_id,
                'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                'chiavi': []
            }
            insert_new_vault = True
        else:
            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            insert_new_vault = False
            
    return insert_new_vault, vault_deciphered
