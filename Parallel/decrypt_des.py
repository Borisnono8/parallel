from Crypto.Cipher import DES
import base64
import csv
import time
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ── Configurazione ──────────────────────────────────────────────
ENCRYPTION_KEY = "MBertini"          # Deve essere esattamente 8 bytes
CSV_PATH       = "passwords.csv"     
PASSWORD_COL   = "password"


# ── Lettura CSV ─────────────────────────────────────────────────

def load_passwords_from_csv(filepath: str, column: str = "password") -> list[dict]:
    """
    Legge le password dal CSV e restituisce una lista di dict
    con tutti i campi originali (es. password, strength).
    """
    path = Path(filepath)
    if not path.exists():
        logging.error(f"File non trovato: {filepath}")
        sys.exit(1)

    records = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            logging.error(f"Colonna '{column}' non trovata. Colonne disponibili: {reader.fieldnames}")
            sys.exit(1)
        for row in reader:
            if row[column].strip():
                records.append(row)

    logging.info(f"Password caricate: {len(records):,}  da '{filepath}'")
    return records


# ── Funzioni DES ────────────────────────────────────────────────

def encrypt_password(password: str, key: str) -> str:
    if len(key) != 8:
        raise ValueError(f"La chiave DES deve essere 8 byte, ricevuto {len(key)}")
    padded = password[:8].ljust(8, "\x00")
    cipher = DES.new(key.encode("utf-8"), DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(padded.encode("utf-8"))).decode("ascii")


def decrypt_password(encrypted_b64: str, key: str) -> str:
    if len(key) != 8:
        raise ValueError(f"La chiave DES deve essere 8 byte, ricevuto {len(key)}")
    cipher = DES.new(key.encode("utf-8"), DES.MODE_ECB)
    raw = cipher.decrypt(base64.b64decode(encrypted_b64))
    return raw.decode("utf-8").rstrip("\x00")


# ── Main ────────────────────────────────────────────────────────

if __name__ == "__main__":
    records = load_passwords_from_csv(CSV_PATH, PASSWORD_COL)
    passwords = [r[PASSWORD_COL] for r in records]

    # ── Cifratura ─────────────────────────────────────────────
    t0 = time.perf_counter()
    encrypted = [encrypt_password(p, ENCRYPTION_KEY) for p in passwords]
    encrypt_time = time.perf_counter() - t0

    # ── Decifratura ───────────────────────────────────────────
    t0 = time.perf_counter()
    decrypted = [decrypt_password(e, ENCRYPTION_KEY) for e in encrypted]
    decrypt_time = time.perf_counter() - t0

    # ── Verifica round-trip ───────────────────────────────────
    # DES tronca a 8 char: confronto corretto solo sui primi 8
    errors = sum(
        1 for orig, dec in zip(passwords, decrypted)
        if orig[:8] != dec
    )

    print(f"\n{'─' * 45}")
    print(f"  Sorgente            : {CSV_PATH}")
    print(f"  Password elaborate  : {len(passwords):,}")
    print(f"  Tempo cifratura     : {encrypt_time:.4f} s")
    print(f"  Tempo decifratura   : {decrypt_time:.4f} s")
    print(f"  Errori round-trip   : {errors}")
    print(f"{'─' * 45}")

    # Mostra le prime 5 come esempio
    print("\n  Esempi (prime 5):")
    print(f"  {'Originale':<20} {'Cifrata (Base64)':<30} {'Decifrata'}")
    print(f"  {'─'*20} {'─'*30} {'─'*20}")
    for orig, enc, dec in zip(passwords[:5], encrypted[:5], decrypted[:5]):
        print(f"  {orig:<20} {enc:<30} {dec}")
    print()

    if errors:
        logging.error(f"{errors} password non coincidono dopo il round-trip!")
    else:
        logging.info("Round-trip OK: tutte le password coincidono.")
