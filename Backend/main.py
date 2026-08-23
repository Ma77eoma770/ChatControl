import asyncio
import random
from fastapi import FastAPI
from database import sqlite as db_setup
from routes import router as api_router
from fastapi.middleware.cors import CORSMiddleware
from core.config import enable_decoy_traffic


# Istanzia l'applicazione FastAPI principale per il backend di ChatControl
app = FastAPI()

# Configurazione del middleware CORS per abilitare le richieste cross-origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:5173",
        "https://127.0.0.1:5173",
        "https://192.168.1.228:5173",
        "https://server.apernici.it",
        "https://apernici.it",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registra il router principale
app.include_router(api_router)


async def periodic_decoy_worker():
    """Worker in background per l'offuscamento temporale tramite il traffico civetta."""
    while True:
        try:
            await asyncio.sleep(random.uniform(60.0, 300.0))
        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    """Inizializza il DB e i servizi di background all'avvio del backend."""
    db_setup.initDB()
    if enable_decoy_traffic:
        asyncio.create_task(periodic_decoy_worker())




	
