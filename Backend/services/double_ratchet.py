import base64
import os
import json
import nacl.secret
import nacl.utils
import nacl.exceptions
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

MAX_SKIP = 1000

def _hkdf(master: bytes, length: int, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or b"\x00" * 32,
        info=info
    ).derive(master)

def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Deriva la nuova Root Key e Chain Key tramite HKDF-SHA256."""
    derived = _hkdf(dh_out, 64, info=b"DoubleRatchetRK", salt=rk)
    return derived[:32], derived[32:]

def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Deriva la nuova Chain Key e Message Key tramite HKDF-SHA256."""
    ck_next = _hkdf(ck, 32, info=b"DoubleRatchetCK_Next")
    mk = _hkdf(ck, 32, info=b"DoubleRatchetCK_MK")
    return ck_next, mk


class DoubleRatchetSession:
    """
    Gestisce uno stato completo di sessione Double Ratchet (Signal Protocol).
    Fornisce Perfect Forward Secrecy e Break-in Recovery.
    """

    def __init__(
        self,
        dhs_priv_b64: str | None = None,
        dhr_pub_b64: str | None = None,
        rk_b64: str | None = None,
        cks_b64: str | None = None,
        ckr_b64: str | None = None,
        ns: int = 0,
        nr: int = 0,
        pn: int = 0,
        mk_skipped: dict | None = None,
    ):
        self.dhs_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(dhs_priv_b64)) if dhs_priv_b64 else X25519PrivateKey.from_private_bytes(os.urandom(32))
        self.dhr_pub = X25519PublicKey.from_public_bytes(base64.b64decode(dhr_pub_b64)) if dhr_pub_b64 else None
        self.rk = base64.b64decode(rk_b64) if rk_b64 else None
        self.cks = base64.b64decode(cks_b64) if cks_b64 else None
        self.ckr = base64.b64decode(ckr_b64) if ckr_b64 else None
        self.ns = ns
        self.nr = nr
        self.pn = pn
        self.mk_skipped = mk_skipped if mk_skipped is not None else {}

    @classmethod
    def init_alice(cls, shared_secret: bytes, bob_dh_pub_b64: str) -> "DoubleRatchetSession":
        """Inizializza la sessione per Alice (chi avvia la prima comunicazione)."""
        dhs_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        bob_pub = X25519PublicKey.from_public_bytes(base64.b64decode(bob_dh_pub_b64))
        dh_out = dhs_priv.exchange(bob_pub)
        rk, cks = kdf_rk(shared_secret, dh_out)

        session = cls()
        session.dhs_priv = dhs_priv
        session.dhr_pub = bob_pub
        session.rk = rk
        session.cks = cks
        session.ckr = None
        session.ns = 0
        session.nr = 0
        session.pn = 0
        session.mk_skipped = {}
        return session

    @classmethod
    def init_bob(cls, shared_secret: bytes, bob_dh_priv_b64: str) -> "DoubleRatchetSession":
        """Inizializza la sessione per Bob (chi riceve il primo messaggio)."""
        session = cls()
        session.dhs_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(bob_dh_priv_b64))
        session.dhr_pub = None
        session.rk = shared_secret
        session.cks = None
        session.ckr = None
        session.ns = 0
        session.nr = 0
        session.pn = 0
        session.mk_skipped = {}
        return session

    def encrypt(self, plaintext: bytes | str) -> dict:
        """Cifra un testo/bytes ed avanza il Symmetric Ratchet di invio."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        if not self.cks:
            raise ValueError("Stato Ratchet non pronto per l'invio (manca CKs)")

        self.cks, mk = kdf_ck(self.cks)
        box = nacl.secret.SecretBox(mk)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc_payload = box.encrypt(plaintext, nonce)

        pub_bytes = self.dhs_priv.public_key().public_bytes_raw()
        header = {
            "dh_pub": base64.b64encode(pub_bytes).decode("utf-8"),
            "pn": self.pn,
            "n": self.ns,
        }
        self.ns += 1

        return {
            "v": "dr_v1",
            "header": header,
            "ciphertext": base64.b64encode(enc_payload).decode("utf-8"),
        }

    def decrypt(self, envelope: dict) -> bytes:
        """Decifra un payload ed avanza il DH ed il Symmetric Ratchet di ricezione."""
        if envelope.get("v") != "dr_v1":
            raise ValueError(f"Versione Double Ratchet non valida: {envelope.get('v')}")

        header = envelope["header"]
        ciphertext_b64 = envelope["ciphertext"]
        dh_pub_b64 = header["dh_pub"]
        pn = header["pn"]
        n = header["n"]

        cipher_bytes = base64.b64decode(ciphertext_b64)

        # 1. Verifica se la chiave messaggio è tra quelle saltate (Skipped Keys)
        skipped_key = (dh_pub_b64, n)
        if skipped_key in self.mk_skipped:
            mk_b64 = self.mk_skipped.pop(skipped_key)
            mk = base64.b64decode(mk_b64)
            box = nacl.secret.SecretBox(mk)
            return box.decrypt(cipher_bytes)

        remote_pub = X25519PublicKey.from_public_bytes(base64.b64decode(dh_pub_b64))

        # 2. Se riceviamo una nuova chiave DH dal mittente, eseguiamo il DH Ratchet
        if self.dhr_pub is None or remote_pub.public_bytes_raw() != self.dhr_pub.public_bytes_raw():
            self._skip_message_keys(pn)
            self._dh_ratchet(remote_pub)

        self._skip_message_keys(n)

        # 3. Avanza il Symmetric Ratchet di ricezione
        if not self.ckr:
            raise ValueError("Stato CKr non disponibile per la decifratura")

        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1

        box = nacl.secret.SecretBox(mk)
        return box.decrypt(cipher_bytes)

    def _skip_message_keys(self, until: int):
        if self.ckr is not None:
            if self.nr + MAX_SKIP < until:
                raise ValueError("Troppi messaggi saltati nel Ratchet")
            while self.nr < until:
                self.ckr, mk = kdf_ck(self.ckr)
                if self.dhr_pub:
                    pub_b64 = base64.b64encode(self.dhr_pub.public_bytes_raw()).decode("utf-8")
                    self.mk_skipped[(pub_b64, self.nr)] = base64.b64encode(mk).decode("utf-8")
                self.nr += 1

    def _dh_ratchet(self, remote_pub: X25519PublicKey):
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = remote_pub

        # ECDH step 1: aggiorna CKr con le chiavi attuali
        dh_out1 = self.dhs_priv.exchange(self.dhr_pub)
        self.rk, self.ckr = kdf_rk(self.rk, dh_out1)

        # ECDH step 2: rigenera la propria chiave DHs ed aggiorna CKs
        self.dhs_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        dh_out2 = self.dhs_priv.exchange(self.dhr_pub)
        self.rk, self.cks = kdf_rk(self.rk, dh_out2)

    def to_dict(self) -> dict:
        """Serializza lo stato della sessione per la persistenza nel vault SQLite."""
        pub_bytes = self.dhs_priv.public_key().public_bytes_raw()
        priv_bytes = self.dhs_priv.private_bytes_raw()
        dhr_b64 = base64.b64encode(self.dhr_pub.public_bytes_raw()).decode("utf-8") if self.dhr_pub else None

        # Converte la mappa mk_skipped in una forma serializzabile JSON
        mk_skipped_serializable = {
            f"{k[0]}:{k[1]}": v for k, v in self.mk_skipped.items()
        }

        return {
            "dhs_priv": base64.b64encode(priv_bytes).decode("utf-8"),
            "dhs_pub": base64.b64encode(pub_bytes).decode("utf-8"),
            "dhr_pub": dhr_b64,
            "rk": base64.b64encode(self.rk).decode("utf-8") if self.rk else None,
            "cks": base64.b64encode(self.cks).decode("utf-8") if self.cks else None,
            "ckr": base64.b64encode(self.ckr).decode("utf-8") if self.ckr else None,
            "ns": self.ns,
            "nr": self.nr,
            "pn": self.pn,
            "mk_skipped": mk_skipped_serializable,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DoubleRatchetSession":
        """Ricostruisce la sessione Double Ratchet a partire da un dizionario deserializzato."""
        mk_skipped_raw = data.get("mk_skipped", {})
        mk_skipped = {}
        for key_str, v in mk_skipped_raw.items():
            parts = key_str.rsplit(":", 1)
            if len(parts) == 2:
                mk_skipped[(parts[0], int(parts[1]))] = v

        return cls(
            dhs_priv_b64=data.get("dhs_priv"),
            dhr_pub_b64=data.get("dhr_pub"),
            rk_b64=data.get("rk"),
            cks_b64=data.get("cks"),
            ckr_b64=data.get("ckr"),
            ns=data.get("ns", 0),
            nr=data.get("nr", 0),
            pn=data.get("pn", 0),
            mk_skipped=mk_skipped,
        )
