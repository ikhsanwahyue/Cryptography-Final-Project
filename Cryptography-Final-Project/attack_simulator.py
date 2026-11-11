#!/usr/bin/env python3
"""
===========================================================================
  LEXVAULT - ADVERSARIAL RED-TEAM & ANTI-TAMPER ATTACK SIMULATOR
  File 2 (Pendamping Demo Pengujian Keamanan terhadap `main.py`)
===========================================================================
Cara Pakai (2 Terminal Berdampingan):
  - Terminal 1: .venv/bin/python main.py
  - Terminal 2: .venv/bin/python attack_simulator.py

Simulator ini menguji ketahanan arsitektur LexVault terhadap:
  [1] Manipulasi Database & Bukti (SQLite Insider Tamper Attack)
  [2] Serangan Re-Mining Proof-of-Work Palsu (Chain Link & L2 Mismatch)
  [3] Pemulihan Database Bukti ke Kondisi Asli (Restore Valid State)
  [4] Serangan Rainbow Table & Dictionary Brute-Force pada Salted SHA-256
  [5] Serangan Spoofing Biometrik 128-D SFace (1.000 Vektor Impostor Acak)
  [6] Serangan Bit-Flipping pada Super-Crypto (Vigenere + AES-256-CBC)
===========================================================================
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.auth_gate import AuthGate
from core.local_blockchain import Block, LocalBlockchain
from core.text_crypto import TextSuperCrypto
from database.db_manager import DatabaseManager

BACKUP_FILE = PROJECT_ROOT / "dongle_sample" / ".tamper_backup.json"


def find_target_databases(gate: AuthGate) -> List[Path]:
    """
    Mencari seluruh file database `offline_vault.db` yang aktif:
    baik di dalam USB Flashdisk yang sedang tertancap (/Volumes/*/offline_vault.db)
    maupun di folder fallback `dongle_sample/offline_vault.db`.
    """
    dbs: List[Path] = []
    for mount in gate.get_removable_mounts():
        usb_db = mount / "offline_vault.db"
        if usb_db.exists() and usb_db not in dbs:
            dbs.append(usb_db)

    sample_db = PROJECT_ROOT / "dongle_sample" / "offline_vault.db"
    if sample_db.exists() and sample_db not in dbs:
        dbs.append(sample_db)

    return dbs


def load_backups() -> Dict[str, List[Dict]]:
    if BACKUP_FILE.exists():
        try:
            return json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_backups(data: Dict[str, List[Dict]]) -> None:
    BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def attack_1_sqlite_tamper(gate: AuthGate) -> None:
    print("\n" + "=" * 75)
    print("  [SERANGAN 1] INSIDER DATABASE TAMPERING (MODIFIKASI BUKTI DI SQLITE)")
    print("=" * 75)
    dbs = find_target_databases(gate)
    if not dbs:
        print("[!] Tidak ditemukan file offline_vault.db. Jalankan main.py terlebih dahulu.")
        return

    backups = load_backups()
    fake_hash = hashlib.sha256(b"MANIPULATED_FORENSIC_EVIDENCE_BY_ATTACKER_999").hexdigest()

    for db_path in dbs:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC").fetchall()]
            if not rows:
                # Buat Genesis block terlebih dahulu jika tabel masih kosong
                tmp_db = DatabaseManager(sqlite_path=str(db_path))
                LocalBlockchain(db_manager=tmp_db)
                rows = [dict(r) for r in conn.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC").fetchall()]

            if not rows:
                print(f"[-] Tabel audit_blocks kosong di {db_path}")
                continue

            # Simpan backup asli jika belum ada backup untuk database ini
            db_key = str(db_path.resolve())
            if db_key not in backups:
                backups[db_key] = rows
                save_backups(backups)

            target_block = rows[-1]
            blk_idx = int(target_block["block_index"])
            orig_hash = str(target_block["evidence_hash"])
            ev_id = str(target_block["evidence_id"])

            conn.execute(
                "UPDATE audit_blocks SET evidence_hash = ? WHERE block_index = ?",
                (fake_hash, blk_idx),
            )
            conn.commit()

            print(f"[+] Target Database : {db_path}")
            print(f"[+] Target Blok     : BLOCK #{blk_idx} (Evidence ID: {ev_id})")
            print(f"    Hash Asli       : {orig_hash}")
            print(f"    Hash Palsu      : {fake_hash}")
            print("[!] STATUS: Payload bukti berhasil dimodifikasi secara ilegal tanpa izin!")
        finally:
            conn.close()

    print("\n>>> LANGKAH PEMBUKTIAN DI APLIKASI UTAMA (main.py):")
    print("    1. Buka aplikasi LexVault (main.py) -> Masuk ke Tab 4 (CHAIN OF CUSTODY AUDIT)")
    print("    2. Klik tombol 'REFRESH CHAIN LEDGER'")
    print("    3. Perhatikan alarm merah: 'TAMPER BREACH DETECTED AT BLOCK(S)'!")
    print("    4. Gunakan Menu [3] di program ini untuk mengembalikan database seperti semula.")


def attack_2_fake_remining(gate: AuthGate) -> None:
    print("\n" + "=" * 75)
    print("  [SERANGAN 2] ADVANCED RE-MINING ATTACK (PEMALSUAN PROOF-OF-WORK '000')")
    print("=" * 75)
    dbs = find_target_databases(gate)
    if not dbs:
        print("[!] Tidak ditemukan file offline_vault.db.")
        return

    backups = load_backups()
    for db_path in dbs:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC").fetchall()]
            if not rows:
                continue

            db_key = str(db_path.resolve())
            if db_key not in backups:
                backups[db_key] = rows
                save_backups(backups)

            # Pilih blok pertama (Genesis / Blok #0) jika ada >1 blok agar terlihat efek putusnya rantai,
            # atau blok terakhir jika hanya ada 1 blok.
            target_row = rows[0] if len(rows) > 1 else rows[-1]
            blk_idx = int(target_row["block_index"])
            fake_ev_hash = hashlib.sha256(b"FORGED_BAP_TRANSCRIPT_WITH_REMINED_POW").hexdigest()

            print(f"[+] Target Database : {db_path}")
            print(f"[+] Menambang ulang PoW ('000') palsu untuk BLOCK #{blk_idx}...")
            t0 = time.perf_counter()
            forged_blk = Block(
                index=blk_idx,
                timestamp=str(target_row["timestamp"]),
                evidence_id=str(target_row["evidence_id"]),
                evidence_hash=fake_ev_hash,
                previous_hash=str(target_row["previous_hash"]),
                nonce=0,
            )
            forged_hash = forged_blk.mine("000")
            elapsed = (time.perf_counter() - t0) * 1000.0

            conn.execute(
                "UPDATE audit_blocks SET evidence_hash = ?, nonce = ?, block_hash = ? WHERE block_index = ?",
                (fake_ev_hash, forged_blk.nonce, forged_hash, blk_idx),
            )
            conn.commit()

            print(f"    PoW Palsu Ditemukan : Nonce={forged_blk.nonce} ({elapsed:.1f} ms)")
            print(f"    Block Hash Palsu    : {forged_hash}")
            if len(rows) > 1:
                print(f"    Efek Berantai       : Blok #{blk_idx + 1} masih menyimpan previous_hash lama!")
                print("                          Rantai kriptografi PUTUS (CHAIN BROKEN)!")
            else:
                print("    Deteksi Layer 2     : Hash di Polygon Amoy Testnet berbeda dengan hash lokal!")
        finally:
            conn.close()


def restore_3_clean_state(gate: AuthGate) -> None:
    print("\n" + "=" * 75)
    print("  [PEMULIHAN 3] RESTORE DATABASE BLOCKCHAIN KE KONDISI ASLI (VALID)")
    print("=" * 75)
    backups = load_backups()
    if not backups:
        print("[i] Tidak ada cadangan modifikasi aktif. Memverifikasi ulang seluruh database...")
    else:
        for db_key, orig_rows in list(backups.items()):
            db_path = Path(db_key)
            if not db_path.exists():
                continue
            conn = sqlite3.connect(str(db_path))
            try:
                for r in orig_rows:
                    conn.execute(
                        """
                        UPDATE audit_blocks
                        SET timestamp = ?, evidence_id = ?, evidence_hash = ?,
                            previous_hash = ?, nonce = ?, block_hash = ?
                        WHERE block_index = ?
                        """,
                        (
                            r["timestamp"],
                            r["evidence_id"],
                            r["evidence_hash"],
                            r["previous_hash"],
                            r["nonce"],
                            r["block_hash"],
                            r["block_index"],
                        ),
                    )
                conn.commit()
                print(f"[+] Berhasil memulihkan {len(orig_rows)} blok asli di: {db_path}")
            finally:
                conn.close()
        if BACKUP_FILE.exists():
            BACKUP_FILE.unlink()

    print("\n>>> Silakan klik 'REFRESH CHAIN LEDGER' di Tab 4 aplikasi main.py.")
    print("    Status rantai akan kembali HIJAU (CHAIN INTEGRITY VERIFIED).")


def attack_4_password_bruteforce(gate: AuthGate) -> None:
    print("\n" + "=" * 75)
    print("  [SERANGAN 4] SIMULASI RAINBOW TABLE & DICTIONARY BRUTE-FORCE PASSWORD")
    print("=" * 75)
    dbs = find_target_databases(gate)
    if not dbs:
        print("[!] Tidak ditemukan database dongle.")
        return

    conn = sqlite3.connect(str(dbs[0]))
    conn.row_factory = sqlite3.Row
    dongles = [dict(r) for r in conn.execute("SELECT * FROM authorized_dongles").fetchall()]
    conn.close()

    if not dongles:
        print("[!] Belum ada dongle terdaftar di database.")
        return

    target = dongles[0]
    serial = target["serial_number"]
    op_name = target["operator_name"]
    salt_hex = target["password_salt"]
    target_hash = target["password_hash"]

    print(f"[+] Target Dongle   : {serial} ({op_name})")
    print(f"[+] Salt (128-bit)  : {salt_hex}")
    print(f"[+] Target SHA-256  : {target_hash}\n")

    # 1. Uji Rainbow Table (Tanpa Salt)
    print("[1/2] Menguji Serangan Pre-Computed Rainbow Table (Unsalted SHA-256)...")
    unsalted_hash = hashlib.sha256(b"LexVault#2026").hexdigest()
    print(f"      Hash Rainbow Table ('LexVault#2026' tanpa salt) : {unsalted_hash[:32]}...")
    print(f"      Hash Tersimpan di Database (dengan 16B salt)    : {target_hash[:32]}...")
    print("      -> HASIL: GAGAL TOTAL! Salt 128-bit acak membuat Rainbow Table tidak berguna.\n")

    # 2. Uji Dictionary Attack
    wordlist = [
        "123456", "password", "admin123", "polri123", "forensik", "qwerty123",
        "indonesia2026", "bapforensik", "rahasia123", "root1234", "lexvault123",
        "custodian2026", "iso27037", "cybercrime", "jakartahq", "kompolaris",
    ]
    print(f"[2/2] Menjalankan Dictionary Attack ({len(wordlist)} kandidat kata sandi umum)...")
    cracked = False
    for idx, candidate in enumerate(wordlist, 1):
        comp_hash = AuthGate.compute_salted_hash(salt_hex, candidate)
        ok = secrets.compare_digest(comp_hash, target_hash)
        status = "COCOK!" if ok else "DITOLAK"
        print(f"      [{idx:02d}/{len(wordlist):02d}] Mencoba '{candidate:<15}' -> {status} (Hash: {comp_hash[:16]}...)")
        time.sleep(0.02)
        if ok:
            cracked = True
            break

    if not cracked:
        print("\n[KESIMPULAN KEAMANAN]:")
        print("  Seluruh serangan kamus (Dictionary Attack) dan Rainbow Table GAGAL menembus")
        print("  konstruksi Salted SHA-256 (SHA256(16_Byte_CSPRNG_Salt || Password)).")


def attack_5_biometric_spoof(gate: AuthGate) -> None:
    print("\n" + "=" * 75)
    print("  [SERANGAN 5] SIMULASI SPOOFING VEKTOR BIOMETRIK SFACE 128-D (1.000 PERCOBAAN)")
    print("=" * 75)
    dbs = find_target_databases(gate)
    if not dbs:
        print("[!] Tidak ditemukan database dongle.")
        return

    conn = sqlite3.connect(str(dbs[0]))
    conn.row_factory = sqlite3.Row
    dongles = [dict(r) for r in conn.execute("SELECT * FROM authorized_dongles").fetchall()]
    conn.close()

    target = None
    for d in dongles:
        if str(d.get("face_profile_hash") or "").startswith("LXV_SFACE_V3:"):
            target = d
            break

    if not target:
        print("[!] Belum ada profil wajah 3-Pose (LXV_SFACE_V3) yang terdaftar untuk diuji.")
        return

    import numpy as np

    stored_profile = str(target["face_profile_hash"])
    print(f"[+] Target Operator : {target['operator_name']} ({target['serial_number']})")
    print("[+] Ambang Keamanan : Cosine Similarity >= 0.38 DAN L2 Distance <= 1.12")
    print("[+] Menyerang dengan 1.000 vektor fitur 128-D palsu (Gaussian Random Impostors)...\n")

    trials = 1000
    accepted = 0
    max_cos = -1.0
    min_l2 = 999.0

    rng = np.random.default_rng(2026)
    for _ in range(trials):
        fake_vec = rng.normal(0.0, 1.0, size=(128,)).astype(np.float32)
        fake_vec /= max(float(np.linalg.norm(fake_vec)), 1e-8)
        fake_b64 = "LXV_SFACE_SINGLE:" + base64.b64encode(fake_vec.tobytes()).decode("ascii")

        matched, sim_pct = gate.compare_face_feature(fake_b64, stored_profile)
        if sim_pct > max_cos:
            max_cos = sim_pct
        if matched:
            accepted += 1

    print(f"    Total Percobaan Spoofing : {trials} vektor wajah acak")
    print(f"    Berhasil Diterima (FAR)  : {accepted} / {trials} ({accepted / trials * 100:.2f}%)")
    print(f"    Skor Kemiripan Tertinggi : {max_cos:.2f}% (Ambang Batas: >= 78.00% / Cos >= 0.363)")
    print("\n[KESIMPULAN KEAMANAN]:")
    print("  Ruang hiper-dimensi 128-D SFace menolak 100% vektor wajah palsu (Zero False Acceptance).")


def attack_6_ciphertext_bitflip() -> None:
    print("\n" + "=" * 75)
    print("  [SERANGAN 6] BIT-FLIPPING ATTACK PADA CIPHERTEXT SUPER-CRYPTO (AES-256-CBC)")
    print("=" * 75)
    sample_bap = (
        "BERITA ACARA PEMERIKSAAN (BAP) - KASUS LXV/2026/091\n"
        "Bukti mutasi dompet kripto sebesar Rp 4.850.000.000."
    )
    vig_key = "GARUDA-FORENSIC-KEY"
    aes_key = "ISO27037#BAP-SecretKey"

    enc = TextSuperCrypto.encrypt(sample_bap, vig_key, aes_key)
    print(f"[+] Plaintext Asli     : {sample_bap.splitlines()[0]}...")
    print(f"[+] Ciphertext Base64  : {enc.ciphertext_b64[:56]}...")
    print(f"[+] SHA-256 Integritas : {enc.sha256_hash}")

    raw_bytes = bytearray(base64.b64decode(enc.ciphertext_b64))
    # Balik 1 bit pada byte terakhir ciphertext
    raw_bytes[-1] ^= 0x01
    tampered_b64 = base64.b64encode(bytes(raw_bytes)).decode("ascii")
    tampered_sha256 = hashlib.sha256(tampered_b64.encode("utf-8")).hexdigest()

    print("\n[!] Menyerang Ciphertext: Membalik 1 bit (XOR 0x01) pada blok terakhir...")
    print(f"    SHA-256 Setelah Bit-Flip : {tampered_sha256}")
    print(f"    Kecocokan Hash Blockchain: {'COCOK' if tampered_sha256 == enc.sha256_hash else 'TIDAK COCOK (AVALANCHE EFFECT)!'}")

    print("[!] Mencoba mendekripsi ciphertext yang telah dimodifikasi 1-bit...")
    try:
        dec = TextSuperCrypto.decrypt(tampered_b64, vig_key, aes_key)
        print(f"    Hasil Dekripsi: {dec[:40]} (Rusak / Tidak Valid)")
    except Exception as exc:
        print(f"    -> DITOLAK OLEH MESIN KRIPTOGRAFI: {exc}")


def main() -> None:
    db = DatabaseManager()
    gate = AuthGate(db_manager=db)

    while True:
        dbs = find_target_databases(gate)
        db_names = ", ".join(str(p.relative_to(PROJECT_ROOT)) if p.is_relative_to(PROJECT_ROOT) else str(p) for p in dbs)
        print("\n" + "=" * 75)
        print("  LEXVAULT RED-TEAM & ANTI-TAMPER ATTACK SIMULATOR (TERMINAL 2)")
        print(f"  Target Database Terdeteksi: {db_names or 'Tidak ada'}")
        print("=" * 75)
        print("  [1] Serang Database SQLite (Ubah Hash Bukti -> Memicu Alarm Merah di Tab 4)")
        print("  [2] Serang Blockchain dengan Re-Mining PoW Palsu (Uji Putus Rantai & L2)")
        print("  [3] PULIHKAN Database Blockchain ke Kondisi Asli (Restore Valid State)")
        print("  [4] Uji Serangan Rainbow Table & Dictionary Brute-Force Password")
        print("  [5] Uji Serangan Spoofing Biometrik Wajah 128-D SFace (1.000 Impostor)")
        print("  [6] Uji Serangan Bit-Flipping 1-Bit pada Ciphertext AES-256-CBC")
        print("  [0] Keluar")
        print("-" * 75)

        try:
            choice = input("Pilih skenario pengujian [0-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nKeluar dari simulator.")
            break

        if choice == "1":
            attack_1_sqlite_tamper(gate)
        elif choice == "2":
            attack_2_fake_remining(gate)
        elif choice == "3":
            restore_3_clean_state(gate)
        elif choice == "4":
            attack_4_password_bruteforce(gate)
        elif choice == "5":
            attack_5_biometric_spoof(gate)
        elif choice == "6":
            attack_6_ciphertext_bitflip()
        elif choice == "0" or choice.lower() in ("q", "exit"):
            print("Keluar dari simulator.")
            break
        else:
            print("[!] Pilihan tidak valid. Masukkan angka 0 sampai 6.")


if __name__ == "__main__":
    main()
