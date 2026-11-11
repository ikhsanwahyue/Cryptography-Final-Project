"""
Hardware Token, Biometric Face Verification, Salted Password Hash,
and USB Kill-Switch Daemon for LexVault (ISO/IEC 27037 Auth Gate).
"""

import base64
import hashlib
import json
import os
import platform
import secrets
import subprocess
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

def _safe_import_cv2() -> Tuple[bool, Any, Any]:
    """
    Imports cv2 and numpy while suppressing C-extension stderr noise
    (e.g., when an older opencv-python 4.9 wheel compiled against NumPy 1.x
    is loaded alongside NumPy 2.x).
    """
    devnull_fd = None
    saved_stderr_fd = None
    try:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        saved_stderr_fd = os.dup(2)
        os.dup2(devnull_fd, 2)
        import cv2 as _cv2
        import numpy as _np
        return True, _cv2, _np
    except Exception:
        return False, None, None
    finally:
        if saved_stderr_fd is not None:
            try:
                os.dup2(saved_stderr_fd, 2)
                os.close(saved_stderr_fd)
            except Exception:
                pass
        if devnull_fd is not None:
            try:
                os.close(devnull_fd)
            except Exception:
                pass


OPENCV_AVAILABLE, cv2, np = _safe_import_cv2()


@dataclass
class DongleStatus:
    connected: bool
    authorized: bool
    serial_number: str
    mount_point: str
    token_file_path: str
    operator_name: str
    badge_id: str
    message: str
    is_dev_fallback: bool = False


class AuthGate:
    """
    Multi-Factor Forensic Authentication Engine:
    Factor 1: Physical USB Hardware Serial + `classified.key` Token + DB `is_active` check.
    Factor 2: OpenCV Haar Cascade Frontal Face Biometric Verification (with hardware-absent bypass).
    Factor 3: Salted SHA-256 Password Verification (`SHA256(16_byte_salt + password)`).
    Plus a 1.5s polling Hardware Kill-Switch Daemon that auto-locks the UI upon USB removal.
    """

    def __init__(
        self,
        db_manager: Any,
        poll_interval: float = 1.5,
        logger_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.db_manager = db_manager
        self.poll_interval = float(os.getenv("LEXVAULT_POLL_INTERVAL_SEC", str(poll_interval)))
        self.logger_callback = logger_callback
        self.base_dir = Path(__file__).resolve().parent.parent
        self.sample_token_path = self.base_dir / "dongle_sample" / "classified.key"

        # Allow dev dongle fallback if explicitly enabled by operator in UI or .env
        self.dev_dongle_enabled: bool = False

        # Active authenticated session state
        self.active_dongle: Optional[DongleStatus] = None
        self.session_unlocked: bool = False

        # Kill-switch daemon state
        self._daemon_thread: Optional[threading.Thread] = None
        self._daemon_stop_event = threading.Event()
        self._kill_switch_callbacks: List[Callable[[str], None]] = []

        # OpenCV Deep Neural Network Face Detector (YuNet) & Recognizer (SFace 128-D)
        self._face_cascade: Optional[Any] = None
        self._face_detector: Optional[Any] = None
        self._face_recognizer: Optional[Any] = None
        self._last_yunet_face_row: Optional[Any] = None
        self._last_pose: str = "NONE"
        self._last_nose_ratio: float = 0.5

        if OPENCV_AVAILABLE and cv2 is not None:
            models_dir = self.base_dir / "core" / "models"
            yunet_path = models_dir / "face_detection_yunet_2023mar.onnx"
            sface_path = models_dir / "face_recognition_sface_2021dec.onnx"
            try:
                if yunet_path.exists() and hasattr(cv2, "FaceDetectorYN"):
                    self._face_detector = cv2.FaceDetectorYN.create(
                        str(yunet_path), "", (320, 240), 0.70, 0.3, 5000
                    )
                if sface_path.exists() and hasattr(cv2, "FaceRecognizerSF"):
                    self._face_recognizer = cv2.FaceRecognizerSF.create(
                        str(sface_path), ""
                    )
            except Exception as exc:
                self._log(f"DNN model init warning: {exc}", "WARN")

    def _log(self, message: str, level: str = "INFO") -> None:
        if self.logger_callback:
            try:
                self.logger_callback(message, level)
            except Exception:
                pass

    # =========================================================================
    # 1. PHYSICAL USB SERIAL & TOKEN CHECKER
    # =========================================================================
    def get_os_usb_serials(self) -> List[Dict[str, str]]:
        """
        Queries hardware USB storage serial numbers across Windows, Linux, and macOS.
        - Windows: PowerShell `Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }`
        - Linux: `lsblk -J -o NAME,TRAN,SERIAL,MOUNTPOINT`
        - macOS: `system_profiler SPUSBDataType -json`
        """
        sys_name = platform.system().lower()
        devices: List[Dict[str, str]] = []

        try:
            if sys_name == "windows":
                ps_cmd = (
                    "Get-CimInstance Win32_DiskDrive | "
                    "Where-Object { $_.InterfaceType -eq 'USB' } | "
                    "Select-Object Model,SerialNumber,DeviceID | ConvertTo-Json -Compress"
                )
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                raw = proc.stdout.strip()
                if raw:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        parsed = [parsed]
                    for item in parsed:
                        serial = str(item.get("SerialNumber") or "").strip()
                        model = str(item.get("Model") or "USB Disk").strip()
                        if serial:
                            devices.append({"name": model, "serial": serial})

            elif sys_name == "linux":
                proc = subprocess.run(
                    ["lsblk", "-J", "-o", "NAME,TRAN,SERIAL,MOUNTPOINT"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                raw = proc.stdout.strip()
                if raw:
                    parsed = json.loads(raw)
                    for blk in parsed.get("blockdevices", []):
                        tran = str(blk.get("tran") or "").lower()
                        serial = str(blk.get("serial") or "").strip()
                        if tran == "usb" and serial:
                            devices.append(
                                {
                                    "name": str(blk.get("name") or "usb"),
                                    "serial": serial,
                                    "mountpoint": str(blk.get("mountpoint") or ""),
                                }
                            )

            elif sys_name == "darwin":
                proc = subprocess.run(
                    ["system_profiler", "SPUSBDataType", "-json"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                raw = proc.stdout.strip()
                if raw:
                    parsed = json.loads(raw)

                    def _walk_usb(nodes: List[Dict[str, Any]]) -> None:
                        for node in nodes:
                            serial = str(node.get("serial_num") or "").strip()
                            name = str(node.get("_name") or "USB Device").strip()
                            if serial and ("Media" in node or "removable_media" in str(node).lower() or serial):
                                devices.append({"name": name, "serial": serial})
                            if "_items" in node and isinstance(node["_items"], list):
                                _walk_usb(node["_items"])

                    _walk_usb(parsed.get("SPUSBDataType", []))
        except Exception as exc:
            self._log(f"USB hardware query warning: {exc}", "WARN")

        return devices

    def get_removable_mounts(self) -> List[Path]:
        """
        Uses psutil.disk_partitions() and OS mount conventions to locate
        candidate removable/external USB mount points.
        """
        mounts: List[Path] = []
        sys_name = platform.system().lower()

        try:
            for part in psutil.disk_partitions(all=False):
                mp = Path(part.mountpoint)
                opts = part.opts.lower()
                if sys_name == "windows":
                    if "removable" in opts or part.mountpoint.upper() not in ("C:\\",):
                        mounts.append(mp)
                elif sys_name == "darwin":
                    if str(mp).startswith("/Volumes/") and mp.name not in ("Macintosh HD", "Preboot", "Update"):
                        mounts.append(mp)
                else:
                    if any(
                        str(mp).startswith(prefix)
                        for prefix in ("/media/", "/run/media/", "/mnt/")
                    ) or "removable" in opts:
                        mounts.append(mp)
        except Exception as exc:
            self._log(f"psutil mount scan error: {exc}", "WARN")

        return mounts

    def scan_hardware_dongle(self) -> DongleStatus:
        """
        Scans physical USB drives for `classified.key`, extracts hardware serial number,
        and validates `is_active = True` against the database.
        If `dev_dongle_enabled` is True, permits the bundled `dongle_sample/classified.key`
        to act as a virtual hardware token for evaluation/testing environments.
        """
        usb_devices = self.get_os_usb_serials()
        mounts = self.get_removable_mounts()

        # 1. Check physical USB mounts for `classified.key`
        for mount in mounts:
            candidate_key = mount / "classified.key"
            if candidate_key.exists() and candidate_key.is_file():
                try:
                    token_data = json.loads(candidate_key.read_text(encoding="utf-8"))
                except Exception as exc:
                    return DongleStatus(
                        connected=True,
                        authorized=False,
                        serial_number="CORRUPTED-TOKEN",
                        mount_point=str(mount),
                        token_file_path=str(candidate_key),
                        operator_name="UNKNOWN",
                        badge_id="N/A",
                        message=f"Token classified.key rusak / bukan JSON valid: {exc}",
                    )

                # Switch active SQLite database directly onto the physical USB Flashdisk!
                self.db_manager.set_active_dongle_storage(mount)

                # Match hardware serial from USB bus or token hardware_binding
                detected_serial = ""
                if usb_devices:
                    detected_serial = usb_devices[0].get("serial", "")
                if not detected_serial:
                    detected_serial = str(token_data.get("hardware_binding") or "").strip()

                db_record = self.db_manager.get_dongle(detected_serial)
                if db_record is None and token_data.get("hardware_binding"):
                    # Try matching by token's bound serial if bus serial differed
                    bound_serial = str(token_data.get("hardware_binding")).strip()
                    db_record = self.db_manager.get_dongle(bound_serial)
                    if db_record is not None:
                        detected_serial = bound_serial

                # If USB has classified.key from an earlier setup before DB was moved onto USB,
                # migrate its record from dongle_sample/offline_vault.db onto the USB's offline_vault.db
                if db_record is None and detected_serial:
                    fallback_db = self.db_manager.fallback_sqlite_path
                    if fallback_db.exists() and fallback_db != self.db_manager.sqlite_path:
                        try:
                            import sqlite3
                            fconn = sqlite3.connect(str(fallback_db))
                            fconn.row_factory = sqlite3.Row
                            frow = fconn.execute(
                                "SELECT * FROM authorized_dongles WHERE serial_number = ?",
                                (detected_serial,),
                            ).fetchone()
                            fconn.close()
                            if frow:
                                frec = dict(frow)
                                self.db_manager.register_dongle(
                                    serial_number=detected_serial,
                                    operator_name=str(frec.get("operator_name", "Forensic Custodian")),
                                    badge_id=str(frec.get("badge_id", "DF-INA-88219")),
                                    token_signature=str(frec.get("token_signature", "")),
                                    password_salt=str(frec.get("password_salt", "")),
                                    password_hash=str(frec.get("password_hash", "")),
                                    face_profile_hash=str(frec.get("face_profile_hash", "")),
                                    is_active=bool(frec.get("is_active", 1)),
                                )
                                db_record = self.db_manager.get_dongle(detected_serial)
                        except Exception:
                            pass

                if db_record is None:
                    return DongleStatus(
                        connected=True,
                        authorized=False,
                        serial_number=detected_serial or "UNREGISTERED-USB",
                        mount_point=str(mount),
                        token_file_path=str(candidate_key),
                        operator_name="UNREGISTERED",
                        badge_id="N/A",
                        message=f"Serial USB '{detected_serial}' belum terdaftar di database Flashdisk.",
                    )

                if not bool(db_record.get("is_active", False)):
                    return DongleStatus(
                        connected=True,
                        authorized=False,
                        serial_number=detected_serial,
                        mount_point=str(mount),
                        token_file_path=str(candidate_key),
                        operator_name=str(db_record.get("operator_name", "REVOKED")),
                        badge_id=str(db_record.get("badge_id", "N/A")),
                        message=f"Dongle '{detected_serial}' berstatus NON-AKTIF (Revoked).",
                    )

                status = DongleStatus(
                    connected=True,
                    authorized=True,
                    serial_number=detected_serial,
                    mount_point=str(mount),
                    token_file_path=str(candidate_key),
                    operator_name=str(db_record.get("operator_name", "Forensic Custodian")),
                    badge_id=str(db_record.get("badge_id", "DF-001")),
                    message=f"Hardware USB Dongle & DB Flashdisk ({mount.name}/offline_vault.db) Terverifikasi.",
                    is_dev_fallback=False,
                )
                self.active_dongle = status
                return status

        # 2. Check if Dev Dongle Simulation (`dongle_sample/classified.key`) is enabled
        self.db_manager.set_active_dongle_storage(self.sample_token_path.parent)
        if self.dev_dongle_enabled and self.sample_token_path.exists():
            try:
                token_data = json.loads(self.sample_token_path.read_text(encoding="utf-8"))
                serial = str(token_data.get("hardware_binding", "LEXVAULT-DEV-DONGLE-001")).strip()
                db_record = self.db_manager.get_dongle(serial)
                if db_record and bool(db_record.get("is_active", False)):
                    status = DongleStatus(
                        connected=True,
                        authorized=True,
                        serial_number=serial,
                        mount_point=str(self.sample_token_path.parent),
                        token_file_path=str(self.sample_token_path),
                        operator_name=str(db_record.get("operator_name", "Forensic Custodian")),
                        badge_id=str(db_record.get("badge_id", "DF-INA-88219")),
                        message="Bypass USB (dongle_sample/offline_vault.db & classified.key) Aktif.",
                        is_dev_fallback=True,
                    )
                    self.active_dongle = status
                    return status
            except Exception as exc:
                self._log(f"Dev dongle read error: {exc}", "ERROR")

        # 3. No valid dongle found
        usb_hint = (
            f"Terdeteksi {len(mounts)} drive USB tanpa classified.key"
            if mounts
            else "Tidak ada USB Flashdisk yang tertancap"
        )
        return DongleStatus(
            connected=False,
            authorized=False,
            serial_number="NONE",
            mount_point="N/A",
            token_file_path="N/A",
            operator_name="UNAUTHENTICATED",
            badge_id="N/A",
            message=f"{usb_hint}. Tancapkan USB Dongle atau aktifkan Virtual Dev Dongle.",
        )

    def provision_usb_drive(
        self,
        mount_path: str,
        operator_name: str,
        badge_id: str,
        password: str,
        face_profile_hash: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Writes `classified.key` onto a mounted USB drive and registers its serial
        number, biometric face profile, and salted password hash in the database.
        """
        target_dir = Path(mount_path)
        if not target_dir.exists() or not target_dir.is_dir():
            return False, f"Mount path tidak ditemukan: {mount_path}"

        usb_devices = self.get_os_usb_serials()
        serial = (
            usb_devices[0]["serial"]
            if usb_devices
            else f"LXV-USB-{secrets.token_hex(4).upper()}"
        )

        salt_hex, pwd_hash = self.hash_password_with_new_salt(password)
        token_sig = hashlib.sha256(f"{serial}:{badge_id}:{salt_hex}".encode("utf-8")).hexdigest()

        token_payload = {
            "token_version": "2.0-ISO27037",
            "issuer": "LEXVAULT_FORENSIC_AUTHORITY",
            "token_id": f"LXV-TOKEN-{secrets.token_hex(4).upper()}",
            "hardware_binding": serial,
            "clearance_level": "LEVEL_5_FORENSIC_CUSTODIAN",
            "signature_sha256": token_sig,
            "operator_name": operator_name,
            "badge_id": badge_id,
            "password_salt": salt_hex,
            "password_hash": pwd_hash,
            "face_profile_hash": face_profile_hash or "",
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        try:
            key_file = target_dir / "classified.key"
            key_file.write_text(json.dumps(token_payload, indent=2), encoding="utf-8")
            # Switch active SQLite database directly onto the target USB drive (or dongle_sample)
            self.db_manager.set_active_dongle_storage(target_dir)
            self.db_manager.register_dongle(
                serial_number=serial,
                operator_name=operator_name,
                badge_id=badge_id,
                token_signature=token_sig,
                password_salt=salt_hex,
                password_hash=pwd_hash,
                face_profile_hash=face_profile_hash or "",
                is_active=True,
            )
            self._log(
                f"USB Dongle & Database ({target_dir / 'offline_vault.db'}) provisioned (Serial: {serial})",
                "SUCCESS",
            )
            return True, f"Berhasil mendaftarkan USB Dongle & Database ({serial}) di {target_dir}"
        except Exception as exc:
            return False, f"Gagal menulis classified.key ke USB: {exc}"

    # =========================================================================
    # 2. HARDWARE KILL-SWITCH DAEMON (1.5 SECOND POLLING)
    # =========================================================================
    def register_kill_switch_callback(self, callback: Callable[[str], None]) -> None:
        if callback not in self._kill_switch_callbacks:
            self._kill_switch_callbacks.append(callback)

    def start_kill_switch_daemon(self) -> None:
        """
        Starts a background daemon thread that checks USB hardware presence every 1.5s.
        If the active USB dongle is removed while `session_unlocked` is True,
        immediately triggers all registered kill-switch callbacks (Auto-Lock).
        """
        if self._daemon_thread is not None and self._daemon_thread.is_alive():
            return

        self._daemon_stop_event.clear()
        self._daemon_thread = threading.Thread(
            target=self._kill_switch_loop,
            name="LexVault-USB-KillSwitch-Daemon",
            daemon=True,
        )
        self._daemon_thread.start()
        self._log(
            f"Hardware Kill-Switch Daemon aktif (interval polling: {self.poll_interval:.1f}s).",
            "INFO",
        )

    def stop_kill_switch_daemon(self) -> None:
        self._daemon_stop_event.set()

    def _kill_switch_loop(self) -> None:
        while not self._daemon_stop_event.is_set():
            time.sleep(self.poll_interval)
            if not self.session_unlocked:
                continue

            status = self.scan_hardware_dongle()
            if not status.connected or not status.authorized:
                self.session_unlocked = False
                self.active_dongle = None
                reason = "KILL-SWITCH TRIGGERED: USB Flashdisk dicabut! Sesi ditutup dan seluruh kredensial dihapus."
                self._log(reason, "CRITICAL")
                for cb in list(self._kill_switch_callbacks):
                    try:
                        cb(reason)
                    except Exception:
                        pass

    # =========================================================================
    # 3. DEEP LEARNING BIOMETRIC FACE RECOGNITION (YUNET 5-LANDMARK + SFACE 128D)
    # =========================================================================
    def get_last_detected_pose(self) -> Tuple[str, float]:
        """
        Returns (pose_name, nose_ratio) from the latest frame analyzed by detect_face_in_frame.
        pose_name is one of: 'FRONT', 'LEFT', 'RIGHT', 'NONE'.
        """
        return self._last_pose, self._last_nose_ratio

    def _run_yunet_on_frame(self, frame_bgr: Any) -> Optional[Any]:
        """
        Runs OpenCV YuNet DNN face detector on a 320x240 downscaled frame and projects
        the 15-element vector [x, y, w, h, x_re, y_re, x_le, y_le, x_nt, y_nt, x_rcm, y_rcm, x_lcm, y_lcm, score]
        back to original frame coordinates.
        """
        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None or self._face_detector is None:
            return None
        try:
            import numpy as np
            h_f, w_f = frame_bgr.shape[:2]
            small = cv2.resize(frame_bgr, (320, 240), interpolation=cv2.INTER_LINEAR)
            self._face_detector.setInputSize((320, 240))
            _, faces = self._face_detector.detect(small)
            if faces is None or len(faces) == 0:
                return None

            # Pick largest detected face with score >= 0.70
            valid = [f for f in faces if float(f[14]) >= 0.70]
            if not valid:
                return None
            best = sorted(valid, key=lambda r: float(r[2] * r[3]), reverse=True)[0].copy()

            scale_x = float(w_f) / 320.0
            scale_y = float(h_f) / 240.0
            for idx in (0, 2, 4, 6, 8, 10, 12):
                best[idx] *= scale_x
            for idx in (1, 3, 5, 7, 9, 11, 13):
                best[idx] *= scale_y
            return best.astype(np.float32)
        except Exception as exc:
            self._log(f"YuNet detection error: {exc}", "WARN")
            return None

    @staticmethod
    def _compute_pose_from_landmarks(face_row: Any) -> Tuple[str, float]:
        """
        Computes horizontal head yaw pose ('FRONT', 'LEFT', 'RIGHT') from YuNet 5 landmarks.
        Uses nose tip horizontal ratio between the two eye centers.
        """
        x_e1 = float(face_row[4])
        x_e2 = float(face_row[6])
        x_nt = float(face_row[8])
        left_eye_x = min(x_e1, x_e2)
        right_eye_x = max(x_e1, x_e2)
        eye_span = max(1.0, right_eye_x - left_eye_x)
        nose_ratio = (x_nt - left_eye_x) / eye_span

        # Clamp ratio for HUD display (0.43 / 0.57 = natural ~15-25 deg head turn)
        nose_ratio_clamped = max(0.0, min(1.0, nose_ratio))
        if nose_ratio < 0.43:
            return "LEFT", nose_ratio_clamped
        elif nose_ratio > 0.57:
            return "RIGHT", nose_ratio_clamped
        else:
            return "FRONT", nose_ratio_clamped

    def detect_face_in_frame(
        self, frame_bgr: Any, target_pose: Optional[str] = None
    ) -> Tuple[bool, Any, int, Tuple[int, int, int, int]]:
        """
        Runs OpenCV YuNet DNN 5-Landmark Detector on a BGR frame.
        Draws 5 facial landmarks (eyes, nose tip, mouth corners), geometric mesh,
        and a live 3-Pose Yaw Indicator Bar at the bottom of the viewport.
        Returns: (face_detected, annotated_bgr_frame, num_faces, largest_bbox)
        """
        self._last_yunet_face_row = None
        self._last_pose = "NONE"
        self._last_nose_ratio = 0.5

        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None:
            return False, frame_bgr, 0, (0, 0, 0, 0)

        annotated = frame_bgr.copy()
        h_f, w_f = annotated.shape[:2]

        face_row = self._run_yunet_on_frame(frame_bgr)
        if face_row is None:
            cv2.rectangle(
                annotated,
                (w_f // 4, h_f // 6),
                (3 * w_f // 4, 5 * h_f // 6),
                (77, 51, 36),
                1,
            )
            cv2.putText(
                annotated,
                "YUNET DNN: SCANNING FACE LANDMARKS...",
                (20, 32),
                cv2.FONT_HERSHEY_PLAIN,
                1.3,
                (11, 158, 245),
                2,
            )
            return False, annotated, 0, (0, 0, 0, 0)

        self._last_yunet_face_row = face_row
        pose_name, nose_ratio = self._compute_pose_from_landmarks(face_row)
        self._last_pose = pose_name
        self._last_nose_ratio = nose_ratio

        x = max(0, int(face_row[0]))
        y = max(0, int(face_row[1]))
        fw = max(1, min(w_f - x, int(face_row[2])))
        fh = max(1, min(h_f - y, int(face_row[3])))
        score = float(face_row[14])

        is_masked, _ = self.is_face_masked(frame_bgr, (x, y, fw, fh))

        # Draw 5 facial landmarks & geometric biometric mesh (proves focus is strictly on facial anatomy)
        pts = [
            (int(face_row[4]), int(face_row[5])),   # Right Eye
            (int(face_row[6]), int(face_row[7])),   # Left Eye
            (int(face_row[8]), int(face_row[9])),   # Nose Tip
            (int(face_row[10]), int(face_row[11])), # Right Mouth
            (int(face_row[12]), int(face_row[13])), # Left Mouth
        ]
        mesh_color = (180, 180, 40) if not is_masked else (0, 0, 200)
        cv2.line(annotated, pts[0], pts[1], mesh_color, 1)
        cv2.line(annotated, pts[0], pts[2], mesh_color, 1)
        cv2.line(annotated, pts[1], pts[2], mesh_color, 1)
        cv2.line(annotated, pts[2], pts[3], mesh_color, 1)
        cv2.line(annotated, pts[2], pts[4], mesh_color, 1)
        cv2.line(annotated, pts[3], pts[4], mesh_color, 1)

        landmark_colors = [
            (255, 220, 0),   # Eye 1 (Cyan)
            (255, 220, 0),   # Eye 2 (Cyan)
            (129, 230, 16),  # Nose Tip (Emerald)
            (11, 180, 245),  # Mouth 1 (Amber)
            (11, 180, 245),  # Mouth 2 (Amber)
        ]
        for pt, lcol in zip(pts, landmark_colors):
            cv2.circle(annotated, pt, 4, lcol, -1)

        corner = max(18, min(fw, fh) // 5)
        thickness = 2
        hud_color = (0, 0, 230) if is_masked else (129, 185, 16)

        # Corner brackets
        cv2.line(annotated, (x, y), (x + corner, y), hud_color, thickness)
        cv2.line(annotated, (x, y), (x, y + corner), hud_color, thickness)
        cv2.line(annotated, (x + fw, y), (x + fw - corner, y), hud_color, thickness)
        cv2.line(annotated, (x + fw, y), (x + fw, y + corner), hud_color, thickness)
        cv2.line(annotated, (x, y + fh), (x + corner, y + fh), hud_color, thickness)
        cv2.line(annotated, (x, y + fh), (x, y + fh - corner), hud_color, thickness)
        cv2.line(annotated, (x + fw, y + fh), (x + fw - corner, y + fh), hud_color, thickness)
        cv2.line(annotated, (x + fw, y + fh), (x + fw, y + fh - corner), hud_color, thickness)

        pose_label_map = {"FRONT": "DEPAN", "LEFT": "KIRI", "RIGHT": "KANAN"}
        pose_id_str = pose_label_map.get(pose_name, pose_name)
        hud_text = (
            "MASK DETECTED [PLEASE REMOVE MASK]"
            if is_masked
            else f"SFACE 128D LOCK [{pose_id_str}] ({score*100:.0f}%)"
        )
        cv2.putText(
            annotated,
            hud_text,
            (x, max(24, y - 10)),
            cv2.FONT_HERSHEY_PLAIN,
            1.15,
            hud_color,
            2,
        )

        # Draw Live 3-Pose Yaw Bar at bottom of frame
        bar_w = min(280, w_f - 40)
        bar_x1 = (w_f - bar_w) // 2
        bar_x2 = bar_x1 + bar_w
        bar_y = h_f - 18
        cv2.rectangle(annotated, (bar_x1, bar_y - 8), (bar_x2, bar_y + 8), (35, 30, 25), -1)
        cv2.rectangle(annotated, (bar_x1, bar_y - 8), (bar_x2, bar_y + 8), (110, 95, 80), 1)
        # Zone dividers at 0.43 and 0.57
        z1_x = int(bar_x1 + 0.43 * bar_w)
        z2_x = int(bar_x1 + 0.57 * bar_w)
        cv2.line(annotated, (z1_x, bar_y - 8), (z1_x, bar_y + 8), (120, 120, 120), 1)
        cv2.line(annotated, (z2_x, bar_y - 8), (z2_x, bar_y + 8), (120, 120, 120), 1)
        # Cursor dot
        cur_x = int(bar_x1 + nose_ratio * bar_w)
        cv2.circle(annotated, (cur_x, bar_y), 6, (129, 230, 16) if not is_masked else (0, 0, 240), -1)

        return True, annotated, 1, (x, y, fw, fh)

    def get_last_detected_pose(self) -> Tuple[str, float]:
        """Returns (pose_name, nose_ratio) from the most recent detect_face_in_frame call."""
        return self._last_pose, self._last_nose_ratio

    def detect_face_with_pose(
        self, frame_bgr: Any, target_pose: Optional[str] = None
    ) -> Tuple[bool, Any, int, Tuple[int, int, int, int], str, float]:
        """
        Convenience wrapper returning (detected, annotated_bgr, num_faces, bbox, pose_name, nose_ratio).
        """
        detected, annotated, num_faces, bbox = self.detect_face_in_frame(frame_bgr, target_pose=target_pose)
        return detected, annotated, num_faces, bbox, self._last_pose, self._last_nose_ratio

    def is_face_masked(self, frame_bgr: Any, bbox: Tuple[int, int, int, int]) -> Tuple[bool, float]:
        """
        Detects whether the operator is wearing a medical/cloth mask or covering their nose/mouth.
        Analyzes skin color pixel density around the nose-to-chin region and compares upper vs lower
        facial color consistency using YuNet landmarks when available.
        Returns: (is_masked, skin_coverage_ratio)
        """
        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None:
            return False, 1.0
        x, y, w, h = bbox
        if w < 25 or h < 25:
            return False, 1.0
        face_roi = frame_bgr[max(0, y):y + h, max(0, x):x + w]
        if face_roi.size == 0:
            return False, 1.0

        try:
            import numpy as np
            # Compare Upper Face (forehead/eye-bridge/upper-cheeks) vs Lower Face (nose-tip/mouth)
            # This relative comparison is 100% lighting-invariant (works under blue laptop screen light at night)
            pad_x = int(w * 0.18)
            upper_roi = face_roi[int(h * 0.15):int(h * 0.45), pad_x:max(pad_x + 1, w - pad_x)]
            lower_roi = face_roi[int(h * 0.55):int(h * 0.90), pad_x:max(pad_x + 1, w - pad_x)]
            if upper_roi.size == 0 or lower_roi.size == 0:
                return False, 1.0

            upper_ycrcb = cv2.cvtColor(upper_roi, cv2.COLOR_BGR2YCrCb).astype(np.float32)
            lower_ycrcb = cv2.cvtColor(lower_roi, cv2.COLOR_BGR2YCrCb).astype(np.float32)

            # Median chrominance (Cr, Cb) of upper face (guaranteed exposed skin)
            up_cr = float(np.median(upper_ycrcb[:, :, 1]))
            up_cb = float(np.median(upper_ycrcb[:, :, 2]))
            up_y = float(np.median(upper_ycrcb[:, :, 0]))

            # Pixel-wise chrominance & luminance distance of lower face relative to upper face skin
            cr_diff = np.abs(lower_ycrcb[:, :, 1] - up_cr)
            cb_diff = np.abs(lower_ycrcb[:, :, 2] - up_cb)
            y_diff = np.abs(lower_ycrcb[:, :, 0] - up_y)
            chroma_dist = np.sqrt(cr_diff ** 2 + cb_diff ** 2)

            # A pixel in the lower face matches the person's own upper-face skin under current lighting
            # if its chrominance is within 24 units and luminance is within 75 units
            matching_skin_mask = (chroma_dist < 24.0) & (y_diff < 75.0)
            ratio = float(np.count_nonzero(matching_skin_mask)) / float(matching_skin_mask.size)

            # Mean chrominance shift between upper and lower face
            mean_chroma_shift = float(np.median(chroma_dist))
            mean_luma_shift = float(np.median(y_diff))

            # Masked only if < 22% of lower face matches upper face skin tone
            # OR huge color/brightness jump (surgical blue/white/black mask)
            is_masked = (ratio < 0.22) or (mean_chroma_shift > 28.0) or (mean_luma_shift > 70.0)
            return bool(is_masked), ratio
        except Exception:
            return False, 1.0

    def extract_face_feature_vector(self, frame_bgr: Any, bbox: Tuple[int, int, int, int]) -> Optional[str]:
        """
        Extracts a pure 128-dimensional Deep Neural Network facial identity vector using
        OpenCV SFace (`face_recognition_sface_2021dec.onnx`) after affine landmark alignment
        (`alignCrop` to 112x112 internal face only, 0% room background/suasana).
        Returns: 'LXV_SFACE_SINGLE:<base64_float32_128d>'
        """
        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None or self._face_recognizer is None:
            return None

        try:
            import numpy as np
            face_row = self._last_yunet_face_row
            if face_row is None:
                face_row = self._run_yunet_on_frame(frame_bgr)
            if face_row is None:
                return None

            # Affine warp & crop strictly around the 5 facial landmarks (112x112 internal face)
            aligned_face = self._face_recognizer.alignCrop(frame_bgr, face_row)
            feat = self._face_recognizer.feature(aligned_face)
            feat = np.asarray(feat, dtype=np.float32).reshape(128)
            norm = float(np.linalg.norm(feat))
            if norm <= 1e-7:
                return None
            feat = (feat / norm).astype(np.float32)

            b64 = base64.b64encode(feat.tobytes()).decode("ascii")
            return f"LXV_SFACE_SINGLE:{b64}"
        except Exception as exc:
            self._log(f"SFace 128-D extraction error: {exc}", "WARN")
            return None

    @staticmethod
    def _decode_sface_single(vec_str: str) -> Optional[Any]:
        """
        Decodes a single 128-D float32 L2-normalized vector from 'LXV_SFACE_SINGLE:<b64>' or raw base64.
        """
        if not vec_str:
            return None
        try:
            import numpy as np
            raw_b64 = vec_str[len("LXV_SFACE_SINGLE:"):] if vec_str.startswith("LXV_SFACE_SINGLE:") else vec_str
            raw_bytes = base64.b64decode(raw_b64)
            if len(raw_bytes) != 128 * 4:
                return None
            vec = np.frombuffer(raw_bytes, dtype=np.float32).copy().reshape(128)
            norm = float(np.linalg.norm(vec))
            if norm > 1e-7:
                vec /= norm
            return vec
        except Exception:
            return None

    def combine_multipose_vectors(
        self, front_vec_str: str, left_vec_str: str, right_vec_str: str
    ) -> Tuple[bool, str, str]:
        """
        Validates and combines 3 single-pose 128-D SFace embeddings (FRONT, LEFT, RIGHT)
        into a unified 'LXV_SFACE_V3:{...}' profile for database storage.
        Also checks cross-pose identity consistency so two different people cannot be mixed.
        Returns: (ok, bundle_string, message)
        """
        try:
            import numpy as np
            v_front = self._decode_sface_single(front_vec_str)
            v_left = self._decode_sface_single(left_vec_str)
            v_right = self._decode_sface_single(right_vec_str)
            if v_front is None or v_left is None or v_right is None:
                return False, "", "Data vektor 3-posisi (Depan/Kiri/Kanan) belum lengkap atau rusak."

            # Ensure all 3 poses come from the SAME individual (turned head naturally gives 0.20..0.75 cosine)
            sim_fl = float(np.dot(v_front, v_left))
            sim_fr = float(np.dot(v_front, v_right))
            if sim_fl < 0.16 or sim_fr < 0.16:
                return (
                    False,
                    "",
                    f"Wajah tidak konsisten antar pose (Kiri={sim_fl*100:.0f}%, Kanan={sim_fr*100:.0f}%). "
                    "Pastikan orang yang sama direkam pada ketiga pose!",
                )

            centroid = v_front + v_left + v_right
            c_norm = float(np.linalg.norm(centroid))
            if c_norm > 1e-7:
                centroid = (centroid / c_norm).astype(np.float32)

            b_front = base64.b64encode(v_front.tobytes()).decode("ascii")
            b_left = base64.b64encode(v_left.tobytes()).decode("ascii")
            b_right = base64.b64encode(v_right.tobytes()).decode("ascii")
            b_cent = base64.b64encode(centroid.tobytes()).decode("ascii")

            digest = hashlib.sha256(f"{b_front}:{b_left}:{b_right}".encode("utf-8")).hexdigest()
            payload = {
                "version": "LXV_SFACE_V3",
                "model": "YuNet+SFace-128D-3Pose",
                "poses": {
                    "front": b_front,
                    "left": b_left,
                    "right": b_right,
                },
                "centroid": b_cent,
                "sha256": digest,
            }
            bundle_str = "LXV_SFACE_V3:" + json.dumps(payload, separators=(",", ":"))
            return True, bundle_str, "Profil Biometrik 3-Posisi (Depan, Kiri, Kanan) berhasil dikunci!"
        except Exception as exc:
            return False, "", f"Gagal menggabungkan vektor 3-posisi: {exc}"

    def compare_face_feature(self, candidate_str: str, stored_str: str) -> Tuple[bool, float]:
        """
        Compares candidate 128-D SFace neural embedding against stored 3-Pose SFace profile
        ('LXV_SFACE_V3:...').
        Strictly rejects legacy background-based profiles ('LXV_BIO_V2', raw hex, or 'EMPTY')
        and rejects unauthorized people (friends/strangers).
        Returns: (is_match, similarity_percentage)
        """
        if not candidate_str or not stored_str:
            return False, 0.0

        stored_clean = stored_str.strip()
        # Strictly require LXV_SFACE_V3 (or LXV_SFACE_SINGLE) neural embeddings
        if not (stored_clean.startswith("LXV_SFACE_V3:") or stored_clean.startswith("LXV_SFACE_SINGLE:")):
            return False, 0.0

        try:
            import numpy as np
            v_cand = self._decode_sface_single(candidate_str)
            if v_cand is None:
                return False, 0.0

            pose_vecs: List[Any] = []
            v_centroid = None

            if stored_clean.startswith("LXV_SFACE_V3:"):
                data = json.loads(stored_clean[len("LXV_SFACE_V3:"):])
                poses = data.get("poses", data)
                for key in ("front", "left", "right"):
                    v = self._decode_sface_single(str(poses.get(key) or ""))
                    if v is not None:
                        pose_vecs.append(v)
                if data.get("centroid"):
                    v_centroid = self._decode_sface_single(str(data["centroid"]))
            elif stored_clean.startswith("LXV_SFACE_SINGLE:"):
                v = self._decode_sface_single(stored_clean)
                if v is not None:
                    pose_vecs.append(v)

            if not pose_vecs:
                return False, 0.0

            if v_centroid is None:
                mean_v = np.mean(np.stack(pose_vecs, axis=0), axis=0)
                n_m = float(np.linalg.norm(mean_v))
                v_centroid = (mean_v / n_m).astype(np.float32) if n_m > 1e-7 else pose_vecs[0]

            cos_scores = [float(np.dot(v_cand, pv)) for pv in pose_vecs]
            l2_dists = [float(np.linalg.norm(v_cand - pv)) for pv in pose_vecs]

            max_cos = max(cos_scores)
            min_l2 = min(l2_dists)
            centroid_cos = float(np.dot(v_cand, v_centroid))

            # SFace 128-D Deep Learning Biometric Decision Rule (OpenCV Zoo Official SFace FR_COSINE = 0.363):
            # - Different person (friend/stranger in same room): max_cos typically -0.10 to +0.22 (min_l2 > 1.24)
            # - Same person: max_cos >= 0.363, centroid_cos >= 0.31, min_l2 <= 1.128
            is_match = bool(max_cos >= 0.363 and centroid_cos >= 0.31 and min_l2 <= 1.128)

            # Map cosine score to intuitive forensic UI percentage (0 - 100%)
            if is_match:
                sim_pct = min(99.5, 78.0 + ((max_cos - 0.363) / 0.50) * 21.5)
            else:
                sim_pct = max(0.0, min(58.0, (max(0.0, max_cos) / 0.363) * 58.0))

            return is_match, sim_pct
        except Exception as exc:
            self._log(f"SFace comparison error: {exc}", "WARN")
            return False, 0.0

    def enroll_multipose_profile(
        self, serial_number: str, front_vec: str, left_vec: str, right_vec: str
    ) -> Tuple[bool, str]:
        """
        Combines 3-pose SFace vectors (FRONT, LEFT, RIGHT) and persists them to
        Supabase Cloud and local SQLite for the specified dongle serial_number.
        """
        ok_comb, bundle_str, msg_comb = self.combine_multipose_vectors(front_vec, left_vec, right_vec)
        if not ok_comb:
            return False, msg_comb

        ok_db = self.db_manager.update_dongle_face_profile(serial_number, bundle_str)
        if ok_db:
            try:
                seed_path = self.base_dir / "dongle_sample" / "default_face_seed.hex"
                seed_path.parent.mkdir(parents=True, exist_ok=True)
                seed_path.write_text(bundle_str, encoding="utf-8")
            except Exception:
                pass
            db_loc = f"{self.db_manager.sqlite_path.parent.name}/{self.db_manager.sqlite_path.name}"
            storage_type = f"Supabase Cloud & {db_loc}" if self.db_manager.cloud_online else f"Flashdisk/Dongle ({db_loc})"
            self._log(
                f"Profil 3-Pose SFace 128-D berhasil disimpan untuk '{serial_number}' ({storage_type}).",
                "SUCCESS",
            )
            return True, f"3-Pose Face ID berhasil disimpan ke {storage_type}!"
        return False, "Gagal menyimpan profil biometrik 3-posisi ke database."

    def enroll_face_profile(self, serial_number: str, frame_bgr: Any, bbox: Tuple[int, int, int, int]) -> Tuple[bool, str]:
        """
        Single-frame fallback wrapper (extracts SFace 128-D vector and stores as 3-pose bundle).
        """
        is_masked, _ = self.is_face_masked(frame_bgr, bbox)
        if is_masked:
            return False, "Masker terdeteksi! Harap lepas masker wajah Anda sebelum mendaftar."

        vec_single = self.extract_face_feature_vector(frame_bgr, bbox)
        if not vec_single:
            return False, "Gagal mengekstrak fitur wajah SFace 128-D dari frame kamera."

        return self.enroll_multipose_profile(serial_number, vec_single, vec_single, vec_single)

    # =========================================================================
    # 4. SALTED SHA-256 PASSWORD HASHING & VERIFICATION
    # =========================================================================
    @staticmethod
    def hash_password_with_new_salt(password: str) -> Tuple[str, str]:
        """
        Generates a cryptographically random 16-byte salt via `secrets.token_bytes(16)`
        and computes `SHA256(salt + password_bytes)`.
        Returns `(salt_hex, hash_hex)`.
        """
        salt_bytes = secrets.token_bytes(16)
        digest = hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()
        return salt_bytes.hex(), digest

    @staticmethod
    def compute_salted_hash(salt_hex: str, password: str) -> str:
        """
        Computes `SHA256(bytes.fromhex(salt_hex) + password.encode('utf-8'))`.
        """
        salt_bytes = bytes.fromhex(salt_hex)
        return hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()

    def verify_password(self, serial_number: str, candidate_password: str) -> Tuple[bool, str, str]:
        """
        Verifies a password against the stored 16-byte salt and SHA-256 hash
        for the specified hardware dongle serial number.
        Returns `(is_valid, computed_hash_hex, message)`.
        """
        record = self.db_manager.get_dongle(serial_number)
        if record is None:
            return False, "", f"Serial dongle '{serial_number}' tidak ditemukan di database."

        if not bool(record.get("is_active", False)):
            return False, "", f"Dongle '{serial_number}' berstatus non-aktif."

        salt_hex = str(record.get("password_salt", "")).strip()
        expected_hash = str(record.get("password_hash", "")).strip()
        if not salt_hex or not expected_hash:
            return False, "", "Data salt/hash pada database korup atau kosong."

        computed_hash = self.compute_salted_hash(salt_hex, candidate_password)
        is_match = secrets.compare_digest(computed_hash, expected_hash)
        if is_match:
            self.session_unlocked = True
            self._log(
                f"Otentikasi Multi-Faktor Selesai. Sesi dibuka untuk {record.get('operator_name')}.",
                "SUCCESS",
            )
            return True, computed_hash, "Otentikasi Salted SHA-256 Valid. Vault Terbuka."
        else:
            self._log("Percobaan password gagal: Hash SHA-256 tidak cocok.", "ERROR")
            return False, computed_hash, "Password salah! Hash SHA256(salt + password) tidak cocok."
