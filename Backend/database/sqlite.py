import sqlite3

DATABASE_NAME = "database.db"
DATABASE_PATH = "database/"+ DATABASE_NAME

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

    # TABELLA PREKEYS: memorizza le chiavi pubbliche per l'inizializzazione asincrona X3DH.
    c.execute("""CREATE TABLE IF NOT EXISTS prekeys (
                username TEXT PRIMARY KEY,
                identity_key_pub TEXT,
                signed_prekey_pub TEXT,
                signed_prekey_sig TEXT,
                FOREIGN KEY (username) REFERENCES utenti(username) ON DELETE CASCADE)"""
              )

    # TABELLA ONE TIME PREKEYS: memorizza le OTPK pubbliche per X3DH.
    c.execute("""CREATE TABLE IF NOT EXISTS one_time_prekeys (
                username TEXT,
                key_id INTEGER,
                pub_key TEXT,
                FOREIGN KEY (username) REFERENCES utenti(username) ON DELETE CASCADE,
                PRIMARY KEY (username, key_id))"""
              )

    # TABELLA SESSIONI RATCHET: memorizza lo stato cifrato delle sessioni 1-a-1 Double Ratchet.
    c.execute("""CREATE TABLE IF NOT EXISTS sessioni_ratchet (
                proprietario TEXT,
                contatto_id TEXT,
                ratchet_vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti(username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, contatto_id))"""
              )

    # TABELLA SESSIONI GRUPPO: predisposizione per le sessioni di gruppo (Envelope Encryption).
    c.execute("""CREATE TABLE IF NOT EXISTS sessioni_gruppo (
                proprietario TEXT,
                gruppo_id TEXT,
                ratchet_vault BLOB,
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
