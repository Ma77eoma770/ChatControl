from fastapi import APIRouter, Cookie, UploadFile, File, Form
from pydantic import BaseModel

from services.message_service import (
    delete_message_logic, send_file_logic, 
    send_message_logic, send_public_key_logic,
    send_decoy_message_logic
)

router = APIRouter()

class MessagePayload(BaseModel):
    text: str
    chat_id: int
    cryph: bool
    group: bool

class DeleteMessage(BaseModel):
    chat_id: int
    message_id: int

class InitKey(BaseModel):
    chat_id: int

class DecoyPayload(BaseModel):
    chat_id: int
    group: bool = False

@router.post("/messages/delete")
async def delete_message(message: DeleteMessage, login_session: str = Cookie(None)):
    """Elimina (revoca) un messaggio dalla chat per tutti gli utenti."""
    return await delete_message_logic(message.chat_id, message.message_id, login_session)

@router.post("/messages/send/file")
async def send_file(
    chat_id: int = Form(...), 
    text: str = Form(""), 
    cryph: bool = Form(False),
    group: bool = Form(False), 
    file: UploadFile = File(...),
    login_session: str = Cookie(None)
):
    """Invia un file multimediale, in chiaro o cifrato."""
    # Passa i dati dell'UploadFile per permettere lo streaming in chunk (V1)
    return await send_file_logic(
        chat_id, text, cryph, group, 
        file, file.filename, file.content_type,
        login_session
    )

@router.post("/messages/send")
async def send_message(credentials: MessagePayload, login_session: str = Cookie(None)):
    """Invia un messaggio di testo, testuale o crittografato (incluso bypass limite telegram tramite payload document)."""
    # Delega la logica di frammentazione, crittografia avanzata e check validità chiavi
    return await send_message_logic(
        credentials.chat_id, credentials.text, credentials.cryph, credentials.group, login_session
    )

@router.post("/messages/initializing")
async def send_public_key(credentials: InitKey, login_session: str = Cookie(None)):
    """Genera una coppia di chiavi per la chat, aggiorna il Vault e invia la chiave pubblica."""
    # Rotta solitamente invocata alla prima apertura di una chat crittografata
    return await send_public_key_logic(credentials.chat_id, login_session)

@router.post("/messages/send/decoy")
async def send_decoy(payload: DecoyPayload, login_session: str = Cookie(None)):
    """Invia un messaggio civetta (decoy/dummy) cifrato per disturbare l'analisi del traffico DPI."""
    return await send_decoy_message_logic(payload.chat_id, login_session, payload.group)
