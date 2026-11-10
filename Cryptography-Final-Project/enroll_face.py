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

def enroll_from_webcam(serial_number: str = "LXV-USB-484BC196"):
    print("=" * 68)
    print("  LEXVAULT - 3-POSE NEURAL FACE ID ENROLLMENT (YUNET + SFACE 128-D)")
    print(f"  Target Dongle / Operator: {serial_number}")
    print("=" * 68)
    print("\n[1/3] Menyalakan webcam...")
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Kamera tidak dapat dibuka. Pastikan izin kamera aktif di System Settings.")
        return False

    db = DatabaseManager()
    gate = AuthGate(db_manager=db)

    print("[2/3] Kamera aktif! Ikuti 3 tahap pemindaian (tanpa masker):")
    print("      Tahap 1: Hadap DEPAN (FRONT)")
    print("      Tahap 2: Menoleh ke KIRI (LEFT)")
    print("      Tahap 3: Menoleh ke KANAN (RIGHT)")
    print("      (Otomatis merekam saat sudut pas, atau tekan [SPASI]). Tekan [ESC]/[Q] untuk batal.\n")

    poses = {"FRONT": None, "LEFT": None, "RIGHT": None}
    pose_hold = 0
    enrolled = False

    while True:
        ret, raw_frame = cap.read()
        if not ret or raw_frame is None:
            continue

        frame = cv2.flip(raw_frame, 1)
        detected, annotated, _, bbox, pose_label, _ = gate.detect_face_with_pose(frame)
        is_masked, _ = gate.is_face_masked(frame, bbox) if detected else (False, 1.0)

        target_pose = "FRONT" if not poses["FRONT"] else ("LEFT" if not poses["LEFT"] else "RIGHT")
        target_id = {"FRONT": "1/3 HADAP DEPAN", "LEFT": "2/3 TOLEH KE KIRI", "RIGHT": "3/3 TOLEH KE KANAN"}[target_pose]

        h, w = annotated.shape[:2]
        if is_masked:
            status_text = "MASKER TERDETEKSI! Lepas masker untuk mendaftar"
            color = (0, 0, 255)
            pose_hold = 0
        elif detected:
            if pose_label == target_pose:
                pose_hold += 1
                status_text = f"[{target_id}] SUDUT PAS ({pose_hold}/3)! Tahan sebentar..."
                color = (0, 255, 0)
            else:
                pose_hold = 0
                status_text = f"Target: [{target_id}] (Saat ini: {pose_label})"
                color = (0, 200, 255)
        else:
            pose_hold = 0
            status_text = f"Target: [{target_id}] - Posisikan wajah di tengah"
            color = (0, 165, 255)

        cv2.putText(annotated, status_text, (18, h - 22), cv2.FONT_HERSHEY_SIMPLEX, 0.58, color, 2)
        cv2.imshow(f"LexVault 3-Pose Face ID ({serial_number})", annotated)

        key = cv2.waitKey(25) & 0xFF
        if key in (27, ord('q'), ord('Q')):
            print("[INFO] Pendaftaran dibatalkan oleh pengguna.")
            break

        should_capture = (pose_hold >= 3) or (key == 32 and detected and not is_masked)
        if should_capture:
            vec = gate.extract_face_feature_vector(frame, bbox)
            if vec:
                poses[target_pose] = vec
                pose_hold = 0
                print(f"  [OK] Pose {target_pose} berhasil direkam!")
                if all(poses.values()):
                    print("\n[3/3] Menggabungkan 3-Pose SFace 128-D & menyimpan ke Supabase Cloud + SQLite...")
                    ok, msg = gate.enroll_multipose_profile(
                        serial_number,
                        poses["FRONT"],
                        poses["LEFT"],
                        poses["RIGHT"],
                    )
                    if ok:
                        print(f"\n[SUKSES] {msg}")
                        cloud_status = "YA (Tersimpan Online)" if db.cloud_online else "OFFLINE (SQLite Lokal)"
                        print(f"[STATUS CLOUD] Supabase Cloud Sync: {cloud_status}")
                        enrolled = True
                        break
                    else:
                        print(f"\n[GAGAL] {msg}")
                        print("        Mengulang pengambilan 3 pose secara otomatis...\n")
                        poses = {"FRONT": None, "LEFT": None, "RIGHT": None}
                        pose_hold = 0

    cap.release()
    cv2.destroyAllWindows()
    return enrolled

def enroll_from_image_file(image_path: str, serial_number: str = "LXV-USB-484BC196"):
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

    is_masked, _ = gate.is_face_masked(frame, bbox)
    if is_masked:
        print("[ERROR] Wajah pada foto terdeteksi memakai masker! Gunakan foto tanpa masker.")
        return False

    ok, msg = gate.enroll_face_profile(serial_number, frame, bbox)
    if ok:
        print(f"[SUKSES] Foto '{p.name}' berhasil didaftarkan ke database untuk {serial_number}!")
        cloud_status = "YA (Tersimpan Online)" if db.cloud_online else "OFFLINE (SQLite Lokal)"
        print(f"[STATUS CLOUD] Supabase Cloud Sync: {cloud_status}")
        vec = gate.extract_face_feature_vector(frame, bbox)
        if vec:
            Path("database/default_face_seed.hex").write_text(vec)
            print("[INFO] Template seeder 'database/default_face_seed.hex' berhasil diperbarui!")
        return True
    else:
        print(f"[GAGAL] {msg}")
        return False

if __name__ == "__main__":
    db = DatabaseManager()
    gate = AuthGate(db_manager=db)
    detected_dongle = gate.scan_hardware_dongle()
    if detected_dongle.connected and detected_dongle.serial_number not in ("NONE", "CORRUPTED-TOKEN"):
        serial = detected_dongle.serial_number
    else:
        serial = os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LXV-USB-484BC196")

    if len(sys.argv) > 1 and sys.argv[1].endswith(('.png', '.jpg', '.jpeg')):
        enroll_from_image_file(sys.argv[1], serial)
    else:
        enroll_from_webcam(serial)

