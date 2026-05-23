import os
import base64
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------------------------------------------------------
# PRIMITIVE CRITTOGRAFICHE
# ---------------------------------------------------------

def generate_dh():
    """Genera una nuova coppia di chiavi Curve25519. Ritorna tuple(priv_bytes, pub_bytes)."""
    priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub.public_bytes_raw()

def dh(priv_key_bytes: bytes, pub_key_bytes: bytes) -> bytes:
    """Esegue lo scambio Diffie-Hellman."""
    priv = X25519PrivateKey.from_private_bytes(priv_key_bytes)
    pub = X25519PublicKey.from_public_bytes(pub_key_bytes)
    return priv.exchange(pub)

def kdf_rk(rk: bytes, dh_out: bytes):
    """KDF per la Root Chain. Ritorna (nuova Root Key, prima Chain Key)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"DoubleRatchetKDF_RK"
    )
    derived = hkdf.derive(dh_out)
    return derived[:32], derived[32:]

def kdf_ck(ck: bytes):
    """KDF per la Sender/Receiver Chain. Ritorna (nuova Chain Key, Message Key)."""
    # Secondo la specifica Signal, si usa HMAC-SHA256 con costanti fisse.
    new_ck = hmac.new(ck, b'\x01', hashlib.sha256).digest()
    mk = hmac.new(ck, b'\x02', hashlib.sha256).digest()
    return new_ck, mk

def encrypt_aead(mk: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """Cifra il payload con ChaCha20-Poly1305 usando la Message Key."""
    aead = ChaCha20Poly1305(mk)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, ad)
    return nonce + ct

def decrypt_aead(mk: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """Decifra il payload. Solleva eccezione in caso di Tag invalido."""
    aead = ChaCha20Poly1305(mk)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return aead.decrypt(nonce, ct, ad)


# ---------------------------------------------------------
# GESTIONE DELLO STATO (Senza OOP, solo dizionari)
# ---------------------------------------------------------

def create_ratchet_state() -> dict:
    """Inizializza un dizionario vuoto che rappresenta lo stato della sessione."""
    return {
        "DHs_priv": None,
        "DHs_pub": None,
        "DHr_pub": None,
        "RK": None,
        "CKs": None,
        "CKr": None,
        "Ns": 0,
        "Nr": 0,
        "PN": 0
    }

def ratchet_init_alice(sk_bytes: bytes, bob_dh_pub_bytes: bytes, alice_ek_priv: bytes, alice_ek_pub: bytes) -> dict:
    """Inizializza lo stato per chi inizia la conversazione (invia il primo messaggio)."""
    print("[DOUBLE RATCHET] Inizializzazione sessione Alice (Iniziatore)...")
    state = create_ratchet_state()
    state["DHs_priv"] = alice_ek_priv
    state["DHs_pub"] = alice_ek_pub
    state["DHr_pub"] = bob_dh_pub_bytes
    
    # Avanza la Root Chain usando il segreto condiviso X3DH
    state["RK"], state["CKs"] = kdf_rk(sk_bytes, dh(state["DHs_priv"], state["DHr_pub"]))
    print(f"[DOUBLE RATCHET] Alice Root Key derivata. Sender Chain inizializzata.")
    return state

def ratchet_init_bob(sk_bytes: bytes, bob_dh_priv_bytes: bytes, bob_dh_pub_bytes: bytes, alice_ek_pub: bytes) -> dict:
    """Inizializza lo stato per chi riceve la conversazione, pre-inizializzando entrambe le chain."""
    print("[DOUBLE RATCHET] Inizializzazione sessione Bob (Ricevente)...")
    state = create_ratchet_state()
    state["DHs_priv"] = bob_dh_priv_bytes
    state["DHs_pub"] = bob_dh_pub_bytes
    state["DHr_pub"] = alice_ek_pub
    
    # Bob calcola subito la Receiver Chain per poter decifrare i messaggi di Alice
    state["RK"], state["CKr"] = kdf_rk(sk_bytes, dh(state["DHs_priv"], state["DHr_pub"]))
    
    # Bob calcola subito una Sender Chain per poter inviare messaggi PRIMA di riceverli
    state["DHs_priv"], state["DHs_pub"] = generate_dh()
    state["RK"], state["CKs"] = kdf_rk(state["RK"], dh(state["DHs_priv"], state["DHr_pub"]))
    
    print(f"[DOUBLE RATCHET] Bob Root Key impostata. Sender e Receiver Chain pre-calcolate.")
    return state

def ratchet_encrypt(state: dict, plaintext: bytes, ad: bytes = b"") -> tuple[dict, str]:
    """
    Esegue il Ratchet Step per l'invio.
    Ritorna un dizionario header e il ciphertext in base64.
    """
    state["CKs"], mk = kdf_ck(state["CKs"])
    
    header = {
        "dh": base64.b64encode(state["DHs_pub"]).decode('utf-8'),
        "n": state["Ns"],
        "pn": state["PN"]
    }
    
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    ad_full = ad + header_json
    
    ciphertext = encrypt_aead(mk, plaintext, ad_full)
    
    print(f"[DOUBLE RATCHET] Cifratura completata (N={state['Ns']}, PN={state['PN']})")
    
    state["Ns"] += 1
    
    return header, base64.b64encode(ciphertext).decode('utf-8')

def ratchet_decrypt(state: dict, header: dict, ciphertext_b64: str, ad: bytes = b"") -> bytes:
    """
    Esegue il Ratchet Step per la ricezione. Implementa logica stateless (no out-of-order dict).
    Ritorna il plaintext.
    """
    try:
        dh_pub_bytes = base64.b64decode(header["dh"])
        n = header["n"]
        pn = header["pn"]
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception as e:
        print(f"[DOUBLE RATCHET] Errore di formato nell'header o ciphertext: {e}")
        raise ValueError("Header o ciphertext non valido")
    
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    ad_full = ad + header_json
    
    # Se il DH del mittente è cambiato, eseguiamo un DHRatchet step
    if state["DHr_pub"] != dh_pub_bytes:
        print("[DOUBLE RATCHET] Ricevuta nuova chiave DH, eseguo DH Ratchet Step...")
        state["PN"] = state["Ns"]
        state["Ns"] = 0
        state["Nr"] = 0
        state["DHr_pub"] = dh_pub_bytes
        
        # Ricalcolo Root Chain per la ricezione
        state["RK"], state["CKr"] = kdf_rk(state["RK"], dh(state["DHs_priv"], state["DHr_pub"]))
        print("[DOUBLE RATCHET] Receiver Chain inizializzata con nuova Root Key.")
        
        # Generiamo nuova coppia DH per il nostro prossimo invio e calcoliamo la nuova Root Key
        state["DHs_priv"], state["DHs_pub"] = generate_dh()
        state["RK"], state["CKs"] = kdf_rk(state["RK"], dh(state["DHs_priv"], state["DHr_pub"]))
        print("[DOUBLE RATCHET] Nuova coppia DH generata. Sender Chain pre-calcolata.")
    
    # Avanziamo la receiving chain per raggiungere il messaggio N
    # Attenzione: i messaggi saltati vengono calcolati per far avanzare la chain, ma SCARTATI.
    while state["Nr"] < n:
        state["CKr"], _ = kdf_ck(state["CKr"])
        print(f"[DOUBLE RATCHET] Attenzione: Messaggio saltato (N={state['Nr']}). Chain Key avanzata.")
        state["Nr"] += 1
        
    state["CKr"], mk = kdf_ck(state["CKr"])
    state["Nr"] += 1
    
    print(f"[DOUBLE RATCHET] Tentativo di decifratura (N={n})...")
    try:
        plaintext = decrypt_aead(mk, ciphertext, ad_full)
        print("[DOUBLE RATCHET] Decifratura AEAD completata con successo.")
        return plaintext
    except Exception as e:
        print(f"[DOUBLE RATCHET] Errore di decifratura (possibile desync o chiave errata): {e}")
        raise ValueError("Decifratura fallita")

# ---------------------------------------------------------
# HELPER PER SERIALIZZAZIONE
# ---------------------------------------------------------

def state_to_dict(state: dict) -> dict:
    """Converte i bytes dello stato in Base64 per il salvataggio in JSON."""
    return {k: base64.b64encode(v).decode('utf-8') if isinstance(v, bytes) else v for k, v in state.items()}

def state_from_dict(data: dict) -> dict:
    """Ripristina lo stato da un dizionario serializzato Base64."""
    return {k: base64.b64decode(v) if isinstance(v, str) and k != 'Ns' and k != 'Nr' and k != 'PN' else v for k, v in data.items()}
