#!/usr/bin/env python3
"""
LexVault - Instant Face Enrollment CLI Tool
Mengambil foto wajah langsung dari webcam atau dari file gambar (JPG/PNG),
mengekstrak vektor biometriknya, dan langsung menyimpannya ke database
(SQLite offline_vault.db dan Supabase Cloud jika terhubung).
"""

import sys
import os
from pathlib import Path

# Pastikan import dari root proyek
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import cv2
from database.db_manager import DatabaseManager
from core.auth_gate import AuthGate

def enroll_from_webcam(serial_number: str = "LEXVAULT-DEV-DONGLE-001"):
    print("=" * 65)
    print("  LEXVAULT - BIOMETRIC FACE ENROLLMENT TOOL")
    print(f"  Target Dongle / Operator: {serial_number}")
    print("=" * 65)
    print("\n[1/3] Menyalakan webcam...")
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Kamera tidak dapat dibuka. Pastikan izin kamera aktif.")
        return False

    db = DatabaseManager()
    gate = AuthGate(db_manager=db)

    print("[2/3] Kamera aktif! Hadapkan wajah ke kamera.")
    print("      Tekan tombol [SPASI] di jendela kamera untuk AMBIL FOTO & DAFTAR.")
    print("      Tekan tombol [ESC] atau [Q] untuk batal.\n")

    enrolled = False
    while True:
        ret, frame = cap.read()
        if not ret or frame is None:
            continue

        detected, annotated, _, bbox = gate.detect_face_in_frame(frame)

        # Tampilkan petunjuk di layar preview
        h, w = annotated.shape[:2]
        if detected:
            status_text = "WAJAH TERKUNCI! Tekan [SPASI] untuk Mendaftar"
            color = (0, 255, 0)
        else:
            status_text = "Mencari wajah... Hadapkan wajah ke kamera"
            color = (0, 165, 255)

        cv2.putText(annotated, status_text, (20, h - 25), cv2.FONT_HERSHEY_SIMPLEX, 0.65, color, 2)
        cv2.imshow("LexVault - Pendaftaran Wajah (Tekan SPASI)", annotated)

        key = cv2.waitKey(20) & 0xFF
        if key in (27, ord('q'), ord('Q')):
            print("[INFO] Pendaftaran dibatalkan oleh pengguna.")
            break
        elif key == 32:  # SPASI
            if not detected or bbox[2] < 30:
                print("[WARN] Wajah belum terdeteksi jelas! Posisikan wajah di tengah kamera.")
                continue

            print("[3/3] Memproses dan menyimpan biometrik ke database...")
            ok, msg = gate.enroll_face_profile(serial_number, frame, bbox)
            if ok:
                print(f"\n[SUKSES] {msg}")
                # Update seeder file juga
                vector_hex = gate.extract_face_feature_vector(frame, bbox)
                if vector_hex:
                    seed_path = Path("database/default_face_seed.hex")
                    seed_path.write_text(vector_hex)
                    print(f"[INFO] Template seeder 'database/default_face_seed.hex' berhasil diperbarui!")
                enrolled = True
            else:
                print(f"\n[GAGAL] {msg}")
            break

    cap.release()
    cv2.destroyAllWindows()
    return enrolled

def enroll_from_image_file(image_path: str, serial_number: str = "LEXVAULT-DEV-DONGLE-001"):
    p = Path(image_path)
    if not p.exists():
        print(f"[ERROR] File foto '{image_path}' tidak ditemukan.")
        return False

    frame = cv2.imread(str(p))
    if frame is None:
        print(f"[ERROR] Gagal membaca gambar '{image_path}'.")
        return False

    db = DatabaseManager()
    gate = AuthGate(db_manager=db)
    detected, _, _, bbox = gate.detect_face_in_frame(frame)
    if not detected:
        print("[ERROR] Wajah tidak terdeteksi di foto tersebut.")
        return False

    ok, msg = gate.enroll_face_profile(serial_number, frame, bbox)
    if ok:
        print(f"[SUKSES] Foto '{p.name}' berhasil didaftarkan ke database untuk {serial_number}!")
        vec = gate.extract_face_feature_vector(frame, bbox)
        if vec:
            Path("database/default_face_seed.hex").write_text(vec)
            print("[INFO] Template seeder 'database/default_face_seed.hex' berhasil diperbarui!")
        return True
    else:
        print(f"[GAGAL] {msg}")
        return False

if __name__ == "__main__":
    serial = os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LEXVAULT-DEV-DONGLE-001")
    if len(sys.argv) > 1 and sys.argv[1].endswith(('.png', '.jpg', '.jpeg')):
        enroll_from_image_file(sys.argv[1], serial)
    else:
        enroll_from_webcam(serial)

