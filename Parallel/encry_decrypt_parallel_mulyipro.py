from Crypto.Cipher import DES
import base64
import csv
import time
import multiprocessing
import functools
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ── Configurazione ──────────────────────────────────────────────
ENCRYPTION_KEY = "NONOPANE"
CSV_PATH       = "passwords.csv"    
PASSWORD_COL   = "password"


# ── Lettura CSV ─────────────────────────────────────────────────

def load_passwords_from_csv(filepath: str, column: str = "password") -> list[str]:
    path = Path(filepath)
    if not path.exists():
        logging.error(f"File non trovato: {filepath}")
        sys.exit(1)

    passwords = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            logging.error(f"Colonna '{column}' non trovata. Colonne: {reader.fieldnames}")
            sys.exit(1)
        for row in reader:
            if row[column].strip():
                passwords.append(row[column])

    logging.info(f"Password caricate: {len(passwords):,}  da '{filepath}'")
    return passwords


# ── Funzioni DES 

def encrypt_password(password: str, key: str) -> str:
    padded = password[:8].ljust(8, "\x00")
    cipher = DES.new(key.encode("utf-8"), DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(padded.encode("utf-8"))).decode("ascii")


def decrypt_password(encrypted_b64: str, key: str) -> str:
    cipher = DES.new(key.encode("utf-8"), DES.MODE_ECB)
    raw = cipher.decrypt(base64.b64decode(encrypted_b64))
    return raw.decode("utf-8").rstrip("\x00")


# ── Utilità ─────────────────────────────────────────────────────

def choose_num_workers(n: int) -> int:
    cpu = multiprocessing.cpu_count()
    if n <= 10_000:
        return 1
    elif n <= 100_000:
        return 2
    elif n <= 1_000_000:
        return max(4, cpu // 2)
    elif n <= 9_000_000:
        return max(8, cpu - 2)
    else:
        return cpu


def optimal_chunksize(n_items: int, n_workers: int) -> int:
    return max(1, n_items // (n_workers * 200))


# ── Main ────────────────────────────────────────────────────────

if __name__ == "__main__":
    passwords = load_passwords_from_csv(CSV_PATH, PASSWORD_COL)
    n = len(passwords)
    num_workers = choose_num_workers(n)
    cs = optimal_chunksize(n, num_workers)

    logging.info(f"Worker: {num_workers}  |  Chunksize: {cs}  |  Password: {n:,}")

    encrypt_fn = functools.partial(encrypt_password, key=ENCRYPTION_KEY)
    decrypt_fn = functools.partial(decrypt_password, key=ENCRYPTION_KEY)

    # ── Cifratura ─────────────────────────────────────────────
    t0 = time.perf_counter()
    with multiprocessing.Pool(processes=num_workers) as pool:
        encrypted = pool.map(encrypt_fn, passwords, chunksize=cs)
    encrypt_time = time.perf_counter() - t0

    # ── Decifratura ───────────────────────────────────────────
    t0 = time.perf_counter()
    with multiprocessing.Pool(processes=num_workers) as pool:
        decrypted = pool.map(decrypt_fn, encrypted, chunksize=cs)
    decrypt_time = time.perf_counter() - t0

    # ── Verifica round-trip ───────────────────────────────────
    errors = sum(1 for orig, dec in zip(passwords, decrypted) if orig[:8] != dec)

    print(f"\n{'─' * 45}")
    print(f"  Sorgente            : {CSV_PATH}")
    print(f"  Worker utilizzati   : {num_workers}")
    print(f"  Password elaborate  : {n:,}")
    print(f"  Tempo cifratura     : {encrypt_time:.4f} s")
    print(f"  Tempo decifratura   : {decrypt_time:.4f} s")
    print(f"  Errori round-trip   : {errors}")
    print(f"{'─' * 45}")

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
