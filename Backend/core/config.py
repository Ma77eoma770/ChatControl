import os, base64
from dotenv import load_dotenv, find_dotenv

# Carica le variabili d'ambiente cercando il file .env nella radice del progetto
env_file = find_dotenv(usecwd=True)
if not env_file:
    env_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
load_dotenv(env_file)

# Pepper crittografico: utilizzato per salare e anonimizzare identificativi (es. chat_id o username) prima dell'inserimento a DB
pepper = os.getenv("SECRET_PEPPER", "9ed4ecb784384de16c2dc5be86818e0b36db355438acd616a45367f50ffca648c4e5793f4b2e3711093b91b54720fb0dc81d11dbed4ceb8c006cdadd5a8efb5d")

# Chiave segreta: utilizzata per la cifratura simmetrica locale (tramite Fernet) di dati sensibili e token di sessione
_env_secret_key = os.getenv("SECRET_KEY")
if _env_secret_key:
    secret_key = _env_secret_key.encode('utf-8')
else:
    secret_key = base64.urlsafe_b64encode(os.urandom(32))

# Configurazione Anti-DPI & Traffic Obfuscation
enable_dpi_obfuscation = os.getenv("ENABLE_DPI_OBFUSCATION", "true").lower() in ("true", "1", "yes")
enable_decoy_traffic = os.getenv("ENABLE_DECOY_TRAFFIC", "true").lower() in ("true", "1", "yes")
jitter_min_ms = int(os.getenv("JITTER_MIN_MS", "20"))
jitter_max_ms = int(os.getenv("JITTER_MAX_MS", "80"))
dpi_buckets = [256, 1024, 4096, 16384, 65536]