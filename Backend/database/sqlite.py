import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_NAME = "database.db"
DATABASE_PATH = os.path.join(BASE_DIR, DATABASE_NAME)

def initDB():
    """Inizializza la base dati creando le tabelle necessarie al funzionamento, se non esistono."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    c = conn.cursor()

    # TABELLA UTENTI: memorizza le utenze della piattaforma.
    # - username: hash (anonimizzato) dello username dell'utente
    # - salt: generato in fase di registrazione, serve a derivare la masterkey dalla password
    # - vault: master vault cifrato simmetricamente contenente le credenziali d'accesso Telegram
    c.execute("""CREATE TABLE IF NOT EXISTS utenti (
                username TEXT PRIMARY KEY, 
                salt TEXT, 
                vault BLOB)"""
              )

    # TABELLA CONTATTI: memorizza le chiavi scambiate per le singole chat private (1 a 1).
    # - contatto_id: hash dell'ID telegram del contatto
    # - vault: sub-vault cifrato contenente la cronologia delle chiavi 'age' scambiate con quel contatto
    c.execute("""CREATE TABLE IF NOT EXISTS contatti (
                proprietario TEXT,
                contatto_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti(username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, contatto_id))"""
              )

    # TABELLA CONTATTI GRUPPO: memorizza le chiavi 'age' all'interno delle chat di gruppo.
    # - gruppo_id: hash dell'ID telegram del gruppo
    # - vault: sub-vault cifrato contenente le chiavi 'age' di tutti i partecipanti al gruppo
    c.execute("""CREATE TABLE IF NOT EXISTS contatti_gruppo (
                proprietario TEXT,
                gruppo_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti (username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, gruppo_id))"""
              )

    conn.commit()

    conn.close()


def get_connection():
    """Restituisce una connessione SQLite con chiavi esterne attive."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
