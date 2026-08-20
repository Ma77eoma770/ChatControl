import asyncio
import json
from fastapi import WebSocket

# temp_id -> chat_id -> set[WebSocket]
# Struttura per gestire connessioni WS multiple aperte dalla stessa utenza per la stessa chat (es. più tab)
_active_connections = {}
_connections_lock = asyncio.Lock()

# temp_id -> chat_id -> {"ids": set[int], "order": list[int]}
# Struttura RAM per deduplicare messaggi recenti o gestire eliminazioni in tempo reale senza dover ricaricare dal DB
_message_index = {}
_message_index_lock = asyncio.Lock()
_MAX_INDEX_PER_CHAT = 3000

async def connect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    """Accetta e registra una nuova connessione WebSocket."""
    await websocket.accept()
    async with _connections_lock:
        user_map = _active_connections.setdefault(temp_id, {})
        sockets = user_map.setdefault(chat_id, set())
        sockets.add(websocket)

async def disconnect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    """Rimuove in modo sicuro una connessione chiusa dalle strutture dati in memoria."""
    async with _connections_lock:
        user_map = _active_connections.get(temp_id)
        if not user_map:
            return
        sockets = user_map.get(chat_id)
        if not sockets:
            return
        sockets.discard(websocket)
        # Pulisce i rami vuoti dell'albero delle connessioni per evitare memory leak
        if not sockets:
            user_map.pop(chat_id, None)
        if not user_map:
            _active_connections.pop(temp_id, None)

async def broadcast_event(temp_id: str, chat_id: int, payload: dict):
    """Invia un payload testuale (JSON) a tutti i socket collegati a determinati temp_id e chat_id."""
    async with _connections_lock:
        sockets = list(_active_connections.get(temp_id, {}).get(chat_id, set()))
    if not sockets:
        return

    # Normalizza e clona il payload una sola volta prima del ciclo
    payload_to_send = json.loads(json.dumps(payload, default=str)) if isinstance(payload, dict) else payload

    dead = []
    for ws in sockets:
        try:
            await ws.send_json(payload_to_send)
        except Exception as e:
            dead.append(ws)
    for ws in dead:
        await disconnect_socket(temp_id, chat_id, ws)

async def index_messages(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.setdefault(temp_id, {})
        chat_map = user_map.setdefault(chat_id, {"ids": set(), "order": []})
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            if mid is None:
                continue
            if mid in ids_set:
                continue
            ids_set.add(mid)
            order.append(mid)
        if len(order) > _MAX_INDEX_PER_CHAT:
            overflow = len(order) - _MAX_INDEX_PER_CHAT
            for _ in range(overflow):
                old = order.pop(0)
                ids_set.discard(old)

async def drop_message_ids(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return
        chat_map = user_map.get(chat_id)
        if not chat_map:
            return
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            ids_set.discard(mid)
        if order:
            chat_map["order"] = [mid for mid in order if mid in ids_set]

async def resolve_chat_id_for_deleted(temp_id: str, message_ids: list[int]) -> int | None:
    if not message_ids:
        return None
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return None
        ids = set(mid for mid in message_ids if mid is not None)
        if not ids:
            return None
        candidates = []
        for chat_id, chat_map in user_map.items():
            if ids.issubset(chat_map["ids"]):
                candidates.append(chat_id)
        if len(candidates) == 1:
            return candidates[0]
        return None
