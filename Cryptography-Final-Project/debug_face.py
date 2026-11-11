#!/usr/bin/env python3
"""
LexVault - Interactive Biometric Face ID Debugger (YuNet 5-Landmark + SFace 128-D)
Menampilkan secara real-time di Jendela Kamera DAN langsung di Terminal:
1. Status profil wajah di SQLite (offline_vault.db) & Supabase Cloud.
2. Potongan murni 112x112 piksel wajah internal (alignCrop - 0% background) di pojok kanan atas layar.
3. Skor Cosine Similarity & L2 Distance terhadap masing-masing pose (FRONT, LEFT, RIGHT, CENTROID).
4. Tombol cepat di jendela kamera:
   - [E]     : Mulai rekam ulang 3-Pose (DEPAN -> KIRI -> KANAN)
   - [SPASI] : Quick-Enroll 1-Klik (langsung simpan wajah saat ini ke semua dongle default)
   - [Q/ESC] : Keluar
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import cv2
import numpy as np
from database.db_manager import DatabaseManager
from core.auth_gate import AuthGate


def run_face_debugger():
    print("=" * 78)
    print("  LEXVAULT - BIOMETRIC FACE ID DIAGNOSTIC & LIVE DEBUGGER (TERMINAL + GUI)")
    print("=" * 78)

    db = DatabaseManager()
    gate = AuthGate(db_manager=db)
    active_dongle = gate.scan_hardware_dongle()

    # 1. Inspect & auto-sync default dongles in active Dongle SQLite (USB Flashdisk or dongle_sample)
    dongles = db.list_dongles()
    print(f"\n[1] STATUS DATABASE DONGLE (Lokasi: {db.sqlite_path} | Cloud Online: {db.cloud_online}):")
    seed_path = PROJECT_ROOT / "dongle_sample" / "default_face_seed.hex"
    seed_str = seed_path.read_text(encoding="utf-8").strip() if seed_path.exists() else ""

    valid_v3_profile = seed_str if seed_str.startswith("LXV_SFACE_V3:") else ""
    for d in dongles:
        fh = str(d.get("face_profile_hash") or "")
        if fh.startswith("LXV_SFACE_V3:") and not valid_v3_profile:
            valid_v3_profile = fh

    for d in dongles:
        sn = d.get("serial_number")
        op = d.get("operator_name")
        fh = str(d.get("face_profile_hash") or "")
        if not fh.startswith("LXV_SFACE_V3:") and valid_v3_profile and sn in ("LXV-USB-484BC196", "LEXVAULT-DEV-DONGLE-001"):
            db.update_dongle_face_profile(sn, valid_v3_profile)
            fh = valid_v3_profile
            print(f"  -> [AUTO-SYNC] Menyalin profil LXV_SFACE_V3 ke dongle '{sn}'")

        status_str = f"VALID LXV_SFACE_V3 ({len(fh)} bytes)" if fh.startswith("LXV_SFACE_V3:") else f"BELUM TERDAFTAR / LAMA ('{fh[:25]}')"
        print(f"  - Serial: {sn:<24} | Operator: {op:<35} | Face: {status_str}")

    active_dongle = gate.scan_hardware_dongle()
    target_serial = (
        active_dongle.serial_number
        if active_dongle.connected and active_dongle.serial_number not in ("NONE", "CORRUPTED-TOKEN")
        else os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LXV-USB-484BC196")
    )
    print(f"\n[2] TARGET DONGLE AKTIF: {target_serial}")
    print("    Kontrol Jendela Kamera (Pastikan klik jendela kamera sebelum tekan tombol):")
    print("    - Tekan [E]     : Rekam Ulang 3-Pose (DEPAN -> KIRI -> KANAN)")
    print("    - Tekan [SPASI] : Quick-Enroll 1-Klik (Simpan Wajah Saat Ini)")
    print("    - Tekan [Q/ESC] : Keluar dari Debugger")
    print("    (Atau jalankan: .venv/bin/python debug_face.py --enroll untuk langsung rekam otomatis)\n")

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Tidak dapat membuka webcam!")
        return

    win_name = "LexVault - Biometric Face Debugger (YuNet + SFace 128-D)"
    cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)
    try:
        cv2.setWindowProperty(win_name, cv2.WND_PROP_TOPMOST, 1)
    except Exception:
        pass

    enroll_mode = "--enroll" in sys.argv
    poses = {"FRONT": None, "LEFT": None, "RIGHT": None}
    pose_hold = 0
    frame_idx = 0

    def load_stored_vectors(serial: str):
        rec = db.get_dongle(serial) or {}
        stored = str(rec.get("face_profile_hash") or "").strip()
        vecs = {}
        centroid = None
        if stored.startswith("LXV_SFACE_V3:"):
            try:
                data = json.loads(stored[len("LXV_SFACE_V3:"):])
                p_dict = data.get("poses", data)
                for k in ("front", "left", "right"):
                    v = gate._decode_sface_single(str(p_dict.get(k) or ""))
                    if v is not None:
                        vecs[k.upper()] = v
                if data.get("centroid"):
                    centroid = gate._decode_sface_single(str(data["centroid"]))
            except Exception as e:
                print(f"[WARN] Gagal decode LXV_SFACE_V3: {e}")
        return stored, vecs, centroid

    stored_str, stored_vecs, stored_centroid = load_stored_vectors(target_serial)

    while True:
        ret, raw_frame = cap.read()
        if not ret or raw_frame is None:
            continue

        frame_idx += 1
        frame = cv2.flip(raw_frame, 1)
        detected, annotated, _, bbox, pose_label, nose_ratio = gate.detect_face_with_pose(frame)
        is_masked, skin_ratio = gate.is_face_masked(frame, bbox) if detected else (False, 1.0)
        h, w = annotated.shape[:2]

        # Tampilkan hasil potongan 112x112 internal face (alignCrop) di pojok kanan atas
        face_row = gate._last_yunet_face_row
        if detected and face_row is not None and gate._face_recognizer is not None:
            try:
                aligned_112 = gate._face_recognizer.alignCrop(frame, face_row)
                if aligned_112 is not None and aligned_112.size > 0:
                    ah, aw = 112, 112
                    x_off = w - aw - 14
                    y_off = 14
                    annotated[y_off:y_off + ah, x_off:x_off + aw] = aligned_112
                    cv2.rectangle(annotated, (x_off - 2, y_off - 2), (x_off + aw + 2, y_off + ah + 2), (255, 220, 0), 2)
                    cv2.putText(annotated, "112x112 PURE FACE", (x_off - 4, y_off + ah + 16), cv2.FONT_HERSHEY_PLAIN, 0.9, (255, 220, 0), 1)
            except Exception:
                pass

        # Panel Telemetri Kiri Atas
        overlay = annotated.copy()
        cv2.rectangle(overlay, (10, 42), (385, 255), (18, 16, 15), -1)
        cv2.addWeighted(overlay, 0.78, annotated, 0.22, 0, annotated)
        cv2.rectangle(annotated, (10, 42), (385, 255), (90, 80, 70), 1)

        y_txt = 62
        cv2.putText(annotated, f"DONGLE : {target_serial}", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.05, (220, 220, 220), 1)
        y_txt += 20
        cv2.putText(annotated, f"POSE   : {pose_label} (Nose Ratio: {nose_ratio:.2f})", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.05, (255, 220, 0), 1)
        y_txt += 20
        mask_col = (0, 0, 255) if is_masked else (120, 230, 80)
        cv2.putText(annotated, f"MASKED : {is_masked} (SkinMatch: {skin_ratio*100:.0f}%)", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.05, mask_col, 1)
        y_txt += 22

        if detected and not is_masked:
            cand_str = gate.extract_face_feature_vector(frame, bbox)
            cand_vec = gate._decode_sface_single(cand_str) if cand_str else None
        else:
            cand_str = None
            cand_vec = None

        cos_f = cos_l = cos_r = cos_c = 0.0
        min_l2 = 9.99
        is_match = False
        sim_pct = 0.0

        if not stored_vecs:
            cv2.putText(annotated, "DB PROFILE: BELUM ADA LXV_SFACE_V3!", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.05, (0, 140, 255), 2)
            y_txt += 22
            cv2.putText(annotated, "-> Tekan [SPASI] atau [E] untuk Daftar!", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.05, (0, 255, 255), 1)
        elif cand_vec is not None:
            cos_f = float(np.dot(cand_vec, stored_vecs["FRONT"])) if "FRONT" in stored_vecs else 0.0
            cos_l = float(np.dot(cand_vec, stored_vecs["LEFT"])) if "LEFT" in stored_vecs else 0.0
            cos_r = float(np.dot(cand_vec, stored_vecs["RIGHT"])) if "RIGHT" in stored_vecs else 0.0
            cos_c = float(np.dot(cand_vec, stored_centroid)) if stored_centroid is not None else 0.0
            min_l2 = min(float(np.linalg.norm(cand_vec - pv)) for pv in stored_vecs.values())
            is_match, sim_pct = gate.compare_face_feature(cand_str, stored_str)

            cv2.putText(annotated, f"COS FRONT: {cos_f:+.3f} | LEFT: {cos_l:+.3f}", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.0, (200, 200, 200), 1)
            y_txt += 18
            cv2.putText(annotated, f"COS RIGHT: {cos_r:+.3f} | CENT: {cos_c:+.3f}", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.0, (200, 200, 200), 1)
            y_txt += 18
            cv2.putText(annotated, f"MIN L2   : {min_l2:.3f} (Limit <= 1.128)", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.0, (200, 200, 200), 1)
            y_txt += 24

            verdict_col = (80, 240, 80) if is_match else (40, 40, 255)
            verdict_txt = f"MATCH! ({sim_pct:.1f}%)" if is_match else f"REJECTED ({sim_pct:.1f}%)"
            cv2.putText(annotated, f"VERDICT  : {verdict_txt}", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.25, verdict_col, 2)
        else:
            cv2.putText(annotated, "WAITING FOR CLEAR UNMASKED FACE...", (20, y_txt), cv2.FONT_HERSHEY_PLAIN, 1.0, (0, 180, 255), 1)

        # Cetak telemetri ke Terminal setiap 12 frame (~0.4 detik) agar terlihat jelas
        if frame_idx % 12 == 0:
            if not detected:
                print(f"[LIVE #{frame_idx:03d}] Face: NO  | Pastikan wajah terlihat di kamera")
            elif is_masked:
                print(f"[LIVE #{frame_idx:03d}] Face: YES | Pose: {pose_label:<5} ({nose_ratio:.2f}) | MASKED=True (SkinMatch={skin_ratio*100:.0f}%)")
            else:
                v_str = f"MATCH! ({sim_pct:.1f}%)" if is_match else f"REJECT ({sim_pct:.1f}%)"
                print(
                    f"[LIVE #{frame_idx:03d}] Face: YES | Pose: {pose_label:<5} ({nose_ratio:.2f}) | "
                    f"Masked: False ({skin_ratio*100:.0f}%) | "
                    f"Cos(F/L/R/C): {cos_f:+.2f}/{cos_l:+.2f}/{cos_r:+.2f}/{cos_c:+.2f} | "
                    f"L2: {min_l2:.2f} | {v_str}"
                )

        # Mode Pendaftaran 3-Pose Interaktif di dalam Debugger
        if enroll_mode:
            target_p = "FRONT" if not poses["FRONT"] else ("LEFT" if not poses["LEFT"] else "RIGHT")
            if detected and not is_masked and pose_label == target_p and cand_str:
                pose_hold += 1
                msg_bar = f"[3-POSE ENROLL] TAHAN POSE {target_p} ({pose_hold}/3)..."
                bar_col = (0, 255, 0)
                if pose_hold >= 3:
                    poses[target_p] = cand_str
                    pose_hold = 0
                    print(f"  >>> [DEBUG-ENROLL] Pose {target_p} BERHASIL DIREKAM!")
                    if all(poses.values()):
                        ok, msg = gate.enroll_multipose_profile(target_serial, poses["FRONT"], poses["LEFT"], poses["RIGHT"])
                        print(f"  >>> [DEBUG-ENROLL] HASIL SIMPAN: {ok} - {msg}\n")
                        stored_str, stored_vecs, stored_centroid = load_stored_vectors(target_serial)
                        enroll_mode = False
            else:
                pose_hold = 0
                msg_bar = f"[3-POSE ENROLL] Arahkan wajah ke: {target_p} (Sekarang: {pose_label})"
                bar_col = (0, 200, 255)
        else:
            msg_bar = "[E]: Rekam 3-Pose | [SPASI]: Quick-Enroll 1-Klik | [Q]: Keluar"
            bar_col = (200, 220, 240)

        cv2.putText(annotated, msg_bar, (16, h - 32), cv2.FONT_HERSHEY_SIMPLEX, 0.52, bar_col, 2)
        cv2.imshow(win_name, annotated)

        key = cv2.waitKey(20) & 0xFF
        if key in (27, ord("q"), ord("Q")):
            break
        elif key in (ord("e"), ord("E")):
            enroll_mode = True
            poses = {"FRONT": None, "LEFT": None, "RIGHT": None}
            pose_hold = 0
            print("\n[INFO] Memulai perekaman ulang 3-Pose (FRONT -> LEFT -> RIGHT)...")
        elif key == 32:  # SPASI = Quick-Enroll 1-Klik
            if detected and not is_masked and cand_str:
                ok, msg = gate.enroll_multipose_profile(target_serial, cand_str, cand_str, cand_str)
                print(f"\n>>> [QUICK-ENROLL SUKSES] {msg}\n")
                stored_str, stored_vecs, stored_centroid = load_stored_vectors(target_serial)
                enroll_mode = False
            else:
                print("\n[WARN] Wajah belum terdeteksi atau masih memakai masker!")

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    run_face_debugger()
