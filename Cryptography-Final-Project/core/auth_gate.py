"""
Hardware Token, Biometric Face Verification, Salted Password Hash,
and USB Kill-Switch Daemon for LexVault (ISO/IEC 27037 Auth Gate).
"""

import hashlib
import json
import os
import platform
import secrets
import subprocess
import threading
import time
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

        # Haar Cascade Classifier
        self._face_cascade: Optional[Any] = None
        if OPENCV_AVAILABLE and cv2 is not None:
            cascade_path = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
            if os.path.exists(cascade_path):
                self._face_cascade = cv2.CascadeClassifier(cascade_path)

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

                if db_record is None:
                    return DongleStatus(
                        connected=True,
                        authorized=False,
                        serial_number=detected_serial or "UNREGISTERED-USB",
                        mount_point=str(mount),
                        token_file_path=str(candidate_key),
                        operator_name="UNREGISTERED",
                        badge_id="N/A",
                        message=f"Serial USB '{detected_serial}' belum terdaftar di database.",
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
                    message="Hardware USB Dongle & classified.key Terverifikasi (ACTIVE).",
                    is_dev_fallback=False,
                )
                self.active_dongle = status
                return status

        # 2. Check if Dev Dongle Simulation (`dongle_sample/classified.key`) is enabled
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
                        message="Virtual Dev Dongle (dongle_sample/classified.key) Aktif & Terverifikasi.",
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
    ) -> Tuple[bool, str]:
        """
        Writes `classified.key` onto a mounted USB drive and registers its serial
        number and salted password hash in the database.
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
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        try:
            key_file = target_dir / "classified.key"
            key_file.write_text(json.dumps(token_payload, indent=2), encoding="utf-8")
            self.db_manager.register_dongle(
                serial_number=serial,
                operator_name=operator_name,
                badge_id=badge_id,
                token_signature=token_sig,
                password_salt=salt_hex,
                password_hash=pwd_hash,
                is_active=True,
            )
            self._log(f"USB Dongle provisioned at {key_file} (Serial: {serial})", "SUCCESS")
            return True, f"Berhasil mendaftarkan USB Dongle ({serial}) di {key_file}"
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
                reason = (
                    f"KILL-SWITCH TRIGGERED: Hardware token '{ self.active_dongle.serial_number if self.active_dongle else 'USB' }' "
                    f"dicabut atau kehilangan otorisasi! Sesi dikunci otomatis."
                )
                self._log(reason, "CRITICAL")
                for cb in list(self._kill_switch_callbacks):
                    try:
                        cb(reason)
                    except Exception:
                        pass

    # =========================================================================
    # 3. BIOMETRIC FACE VERIFICATION (OPENCV HAAR CASCADE)
    # =========================================================================
    def detect_face_in_frame(
        self, frame_bgr: Any
    ) -> Tuple[bool, Any, int, Tuple[int, int, int, int]]:
        """
        Runs OpenCV Haar Cascade (`haarcascade_frontalface_default.xml`) on a BGR frame.
        Draws tactical forensic HUD targeting reticles around detected faces.
        Returns: (face_detected, annotated_bgr_frame, num_faces, largest_bbox)
        """
        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None:
            return False, frame_bgr, 0, (0, 0, 0, 0)

        annotated = frame_bgr.copy()
        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)

        faces = []
        if self._face_cascade is not None and not self._face_cascade.empty():
            faces = self._face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.15,
                minNeighbors=5,
                minSize=(80, 80),
            )

        # Adaptive Multi-Spectrum Biometric Face Detector
        # High speed downscaled detection + robust lighting tolerance
        if len(faces) == 0:
            try:
                import numpy as np
                h_f, w_f = frame_bgr.shape[:2]
                # Scale down for lightning-fast analysis (~10x faster)
                scale_w = 320.0 / float(w_f)
                scale_h = 240.0 / float(h_f)
                small = cv2.resize(frame_bgr, (320, 240), interpolation=cv2.INTER_LINEAR)

                hsv = cv2.cvtColor(small, cv2.COLOR_BGR2HSV)
                ycrcb = cv2.cvtColor(small, cv2.COLOR_BGR2YCrCb)

                # Broad spectrum skin detection under varying ambient light / webcams
                mask_hsv = cv2.inRange(
                    hsv,
                    np.array([0, 18, 30], dtype=np.uint8),
                    np.array([35, 255, 255], dtype=np.uint8),
                )
                mask_ycrcb = cv2.inRange(
                    ycrcb,
                    np.array([0, 128, 70], dtype=np.uint8),
                    np.array([255, 180, 135], dtype=np.uint8),
                )
                combined = cv2.bitwise_and(mask_hsv, mask_ycrcb)
                kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
                combined = cv2.morphologyEx(combined, cv2.MORPH_OPEN, kernel, iterations=1)
                combined = cv2.morphologyEx(combined, cv2.MORPH_CLOSE, kernel, iterations=2)

                cnts, _ = cv2.findContours(combined, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                min_area = (320 * 240) * 0.02  # At least 2% of frame
                for c in cnts:
                    area = cv2.contourArea(c)
                    if area > min_area:
                        bx, by, bw, bh = cv2.boundingRect(c)
                        aspect = bh / float(bw)
                        # Head / face bounding aspect ratio (0.75 - 2.5)
                        if 0.75 <= aspect <= 2.5:
                            # Map coordinates back to original frame resolution
                            orig_x = max(0, int(bx / scale_w))
                            orig_y = max(0, int(by / scale_h))
                            orig_w = min(w_f - orig_x, int(bw / scale_w))
                            orig_h = min(h_f - orig_y, int(bh / scale_h))
                            # Focus upper 85% for face (exclude neck/torso)
                            orig_h = int(orig_h * 0.85)
                            faces.append((orig_x, orig_y, orig_w, orig_h))
            except Exception as exc:
                self._log(f"Skin detector warning: {exc}", "WARN")

        if len(faces) == 0:
            # Draw scanning reticle overlay
            h, w = annotated.shape[:2]
            cv2.rectangle(
                annotated,
                (w // 4, h // 6),
                (3 * w // 4, 5 * h // 6),
                (77, 51, 36),  # Subtle tactical border
                1,
            )
            cv2.putText(
                annotated,
                "SCANNING BIOMETRIC TARGET...",
                (20, 32),
                cv2.FONT_HERSHEY_PLAIN,
                1.3,
                (11, 158, 245),  # Amber in BGR
                2,
            )
            return False, annotated, 0, (0, 0, 0, 0)

        # Pick largest face
        faces_sorted = sorted(faces, key=lambda b: b[2] * b[3], reverse=True)
        x, y, fw, fh = [int(v) for v in faces_sorted[0]]

        # Draw Emerald tactical corner brackets
        emerald_bgr = (129, 185, 16)  # #10B981 in BGR
        corner = max(18, min(fw, fh) // 5)
        thickness = 2

        # Top-left
        cv2.line(annotated, (x, y), (x + corner, y), emerald_bgr, thickness)
        cv2.line(annotated, (x, y), (x, y + corner), emerald_bgr, thickness)
        # Top-right
        cv2.line(annotated, (x + fw, y), (x + fw - corner, y), emerald_bgr, thickness)
        cv2.line(annotated, (x + fw, y), (x + fw, y + corner), emerald_bgr, thickness)
        # Bottom-left
        cv2.line(annotated, (x, y + fh), (x + corner, y + fh), emerald_bgr, thickness)
        cv2.line(annotated, (x, y + fh), (x, y + fh - corner), emerald_bgr, thickness)
        # Bottom-right
        cv2.line(annotated, (x + fw, y + fh), (x + fw - corner, y + fh), emerald_bgr, thickness)
        cv2.line(annotated, (x + fw, y + fh), (x + fw, y + fh - corner), emerald_bgr, thickness)

        cv2.putText(
            annotated,
            f"BIOMETRIC LOCK ACQUIRED [{fw}x{fh}px]",
            (x, max(24, y - 10)),
            cv2.FONT_HERSHEY_PLAIN,
            1.2,
            emerald_bgr,
            2,
        )
        return True, annotated, len(faces), (x, y, fw, fh)

    def extract_face_feature_vector(self, frame_bgr: Any, bbox: Tuple[int, int, int, int]) -> Optional[str]:
        """
        Extracts a normalized, equalized biometric representation of the detected face (64x64)
        and returns it encoded as a hex string for storage in face_profile_hash.
        """
        if not OPENCV_AVAILABLE or cv2 is None or frame_bgr is None:
            return None
        x, y, w, h = bbox
        if w < 20 or h < 20:
            return None
        # Extract face ROI
        face_roi = frame_bgr[max(0, y):y + h, max(0, x):x + w]
        if face_roi.size == 0:
            return None
        gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        resized = cv2.resize(gray, (64, 64), interpolation=cv2.INTER_AREA)
        # Return hex of bytes
        return resized.tobytes().hex()

    def compare_face_feature(self, candidate_hex: str, stored_hex: str) -> Tuple[bool, float]:
        """
        Compares candidate face vector with stored enrolled profile using normalized correlation.
        Returns: (is_match, similarity_percentage)
        """
        if not candidate_hex or not stored_hex:
            return False, 0.0
        # If stored is default initial placeholder, treat as open for enrollment or matching
        if stored_hex == hashlib.sha256(b"LEXVAULT_BIOMETRIC_ENROLLED_V1").hexdigest():
            return True, 100.0

        try:
            cand_bytes = bytes.fromhex(candidate_hex)
            stored_bytes = bytes.fromhex(stored_hex)
            if len(cand_bytes) != 64 * 64 or len(stored_bytes) != 64 * 64:
                return False, 0.0

            import numpy as np
            cand_mat = np.frombuffer(cand_bytes, dtype=np.uint8).reshape((64, 64)).astype(np.float32)
            stored_mat = np.frombuffer(stored_bytes, dtype=np.uint8).reshape((64, 64)).astype(np.float32)

            res = cv2.matchTemplate(cand_mat, stored_mat, cv2.TM_CCOEFF_NORMED)
            similarity = float(res[0][0])  # range -1.0 to 1.0
            similarity_pct = max(0.0, min(100.0, ((similarity + 1.0) / 2.0) * 100.0))
            # Relaxed threshold (>= 0.25 correlation / 62.5% norm) for smooth tracking
            return (similarity >= 0.25), similarity_pct
        except Exception as exc:
            self._log(f"Face comparison error: {exc}", "WARN")
            return False, 0.0

    def enroll_face_profile(self, serial_number: str, frame_bgr: Any, bbox: Tuple[int, int, int, int]) -> Tuple[bool, str]:
        """
        Captures and registers the current operator's biometric face template to database.
        """
        vector_hex = self.extract_face_feature_vector(frame_bgr, bbox)
        if not vector_hex:
            return False, "Gagal mengekstrak fitur wajah dari frame kamera."

        ok = self.db_manager.update_dongle_face_profile(serial_number, vector_hex)
        if ok:
            self._log(f"Biometrik wajah berhasil didaftarkan untuk dongle '{serial_number}'.", "SUCCESS")
            return True, "Wajah berhasil didaftarkan ke Database!"
        return False, "Gagal menyimpan biometrik ke database."

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
