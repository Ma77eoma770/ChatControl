from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse

from services.auth_service import is_logged_in
from services.realtime_service import connect_socket, disconnect_socket, register_telethon_handlers
from services.chat_service import (
    get_chats_logic, get_chat_messages_logic, get_init_messages_logic, 
    download_media_logic, download_encrypt_media_logic
)

router = APIRouter()

@router.websocket("/ws/chats/{chat_id}")
async def chat_events(websocket: WebSocket, chat_id: int):
    """Endpoint WebSocket per eventi in tempo reale della chat."""
    # Recupera il cookie di sessione crittografato
    login_session = websocket.cookies.get("login_session")
    try:
        # Verifica l'autenticità della sessione senza aggiornare l'"ultimo accesso" via HTTP
        temp_id, data = is_logged_in(login_session, False)
    except HTTPException:
        # Chiude forzatamente con codice 1008 (Policy Violation) se la sessione è invalida
        await websocket.close(code=1008)
        return

    client = data["client"]
    # Assicurati che l'istanza Telethon sia connessa
    if not client.is_connected():
        await client.connect()

    # Registra i listener sugli eventi di Telegram per inoltrarli ai WebSocket attivi
    register_telethon_handlers(client, temp_id, login_session)
    # Aggiunge questo socket alla lista di ascoltatori per la chat specifica
    await connect_socket(temp_id, chat_id, websocket)
    try:
        while True:
            # Mantieni la connessione viva, consumando gli eventuali messaggi mandati dal client
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        # Disconnette il socket senza azzerare l'insieme dei messaggi anti-replay
        await disconnect_socket(temp_id, chat_id, websocket)

@router.get("/chats")
async def get_chats(login_session: str = Cookie(None), offset_date: str = None):
    """Recupera l'elenco delle chat con flag cifratura."""
    return await get_chats_logic(login_session, offset_date)

@router.get("/chats/{chat_id}/limit/{limit}/start/{start}")
async def get_chat_messages(chat_id: int, limit: int, start: int, login_session: str = Cookie(None)):
    """Raccoglie messaggi smistando i payload cifrati con security validation."""
    return await get_chat_messages_logic(chat_id, limit, start, login_session)

@router.get("/chats/{chat_id}/inits")
async def get_init_messages(chat_id: int, login_session: str = Cookie(None)):
    """Sonda messaggi di init per aggiornare le variazioni del vault e keys."""
    return await get_init_messages_logic(chat_id, login_session)

@router.get("/media/download/{chat_id}/{message_id}")
async def download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    """Streaming efficiente per file multimediali standard."""
    return await download_media_logic(chat_id, message_id, login_session)

@router.get("/media/cifrato/download/{chat_id}/{message_id}")
async def download_encrypt_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    """Decifra on-the-fly un file offuscato con age e lo streama al client."""
    return await download_encrypt_media_logic(chat_id, message_id, login_session)
