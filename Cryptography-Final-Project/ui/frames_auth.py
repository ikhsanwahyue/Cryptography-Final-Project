"""
Multi-Factor Authentication Screens for LexVault (`ui/frames_auth.py`):
- Screen 1: USB Hardware Serial & `classified.key` Token Verification
- Screen 2: OpenCV Haar Cascade Face Biometric Scanning Preview (with absent-webcam bypass)
- Screen 3: Salted SHA-256 Password Hash Authentication
"""

from tkinter import filedialog
from typing import Any, Callable, Optional

import customtkinter as ctk
from PIL import Image

from core.auth_gate import OPENCV_AVAILABLE, AuthGate, DongleStatus, cv2
from ui.components import (
    COLOR_AMBER,
    COLOR_BASE,
    COLOR_BORDER,
    COLOR_CRIMSON,
    COLOR_EMERALD,
    COLOR_PRIMARY,
    COLOR_PRIMARY_HOVER,
    COLOR_SURFACE,
    COLOR_SURFACE_DARK,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    HUDCard,
    StatusBadge,
    get_mono_font,
)


class AuthWizardFrame(ctk.CTkFrame):
    """
    Three-Screen Forensic Multi-Factor Authentication Gate:
    Stage 1 -> Hardware USB Token & Serial Check
    Stage 2 -> Biometric Face Recognition (Haar Cascade + Fallback Bypass)
    Stage 3 -> Salted SHA-256 Master Password Verification
    """

    def __init__(
        self,
        master: Any,
        auth_gate: AuthGate,
        on_authenticated: Callable[[DongleStatus], None],
        log_callback: Callable[[str, str], None],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=COLOR_BASE, **kwargs)
        self.auth_gate = auth_gate
        self.on_authenticated = on_authenticated
        self.log = log_callback

        self.current_step: int = 1
        self.verified_dongle: Optional[DongleStatus] = None
        self.biometric_verified: bool = False

        # Webcam capture state
        self._cap: Optional[Any] = None
        self._camera_running: bool = False
        self._last_raw_frame: Optional[Any] = None
        self._last_bbox: Tuple[int, int, int, int] = (0, 0, 0, 0)
        # Consecutive frame lock requirement
        self._face_lock_counter: int = 0
        self._required_face_frames: int = 6
        self._cam_ctk_image: Optional[ctk.CTkImage] = None

        self._build_layout()
        self.show_step(1)

    def _build_layout(self) -> None:
        # Step Progress Bar Header
        self.step_header = HUDCard(
            self,
            title="ISO/IEC 27037 MULTI-FACTOR CUSTODY GATE",
            subtitle="3-STAGE ZERO-TRUST HARDWARE & BIOMETRIC VERIFICATION",
        )
        self.step_header.pack(fill="x", padx=20, pady=(14, 10))

        indicators_row = ctk.CTkFrame(self.step_header, fg_color="transparent")
        indicators_row.pack(fill="x", padx=14, pady=(4, 12))

        self.badge_step1 = StatusBadge(
            indicators_row, text="STAGE 1: USB HARDWARE TOKEN", status="WARN"
        )
        self.badge_step1.pack(side="left", padx=(0, 12))

        self.badge_step2 = StatusBadge(
            indicators_row, text="STAGE 2: HAAR BIOMETRIC SCAN", status="INFO"
        )
        self.badge_step2.pack(side="left", padx=(0, 12))

        self.badge_step3 = StatusBadge(
            indicators_row, text="STAGE 3: SALTED SHA-256 KEY", status="INFO"
        )
        self.badge_step3.pack(side="left")

        # Container for active screen
        self.screen_container = ctk.CTkFrame(self, fg_color="transparent")
        self.screen_container.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        self._build_screen1()
        self._build_screen2()
        self._build_screen3()

    # =========================================================================
    # SCREEN 1: USB HARDWARE CHECKING & TOKEN VALIDATION
    # =========================================================================
    def _build_screen1(self) -> None:
        self.screen1 = HUDCard(
            self.screen_container,
            title="SCREEN 1 // PHYSICAL USB DONGLE & SERIAL AUTHENTICATION",
            subtitle="Requires classified.key & active DB serial registration",
        )

        body = ctk.CTkFrame(self.screen1, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=10)

        # Left column: Hardware Telemetry
        left_col = ctk.CTkFrame(
            body, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6
        )
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=4)

        ctk.CTkLabel(
            left_col,
            text="USB HARDWARE BUS TELEMETRY",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_PRIMARY,
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self.lbl_usb_status = StatusBadge(left_col, text="WAITING FOR DONGLE SCAN", status="WARN")
        self.lbl_usb_status.pack(anchor="w", padx=14, pady=(0, 10))

        self.usb_details_box = ctk.CTkTextbox(
            left_col,
            height=190,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(12, "normal"),
            text_color=COLOR_TEXT_PRIMARY,
        )
        self.usb_details_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.usb_details_box.configure(state="disabled")

        # Right column: Controls & Provisioning
        right_col = ctk.CTkFrame(
            body, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6, width=360
        )
        right_col.pack(side="right", fill="y", padx=(10, 0), pady=4)
        right_col.pack_propagate(False)

        ctk.CTkLabel(
            right_col,
            text="HARDWARE TOKEN CONTROLS",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", padx=14, pady=(12, 8))

        self.btn_scan_usb = ctk.CTkButton(
            right_col,
            text="↻ SCAN PHYSICAL USB DONGLE",
            font=get_mono_font(12, "bold"),
            height=38,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self.refresh_usb_status,
        )
        self.btn_scan_usb.pack(fill="x", padx=14, pady=(0, 10))

        # Dev Dongle Switch for testing when no physical USB drive is inserted
        self.dev_dongle_var = ctk.BooleanVar(value=self.auth_gate.dev_dongle_enabled)
        self.switch_dev_dongle = ctk.CTkSwitch(
            right_col,
            text="Mount Virtual Dev Dongle\n(dongle_sample/classified.key)",
            font=get_mono_font(11, "bold"),
            variable=self.dev_dongle_var,
            progress_color=COLOR_EMERALD,
            command=self._on_toggle_dev_dongle,
        )
        self.switch_dev_dongle.pack(anchor="w", padx=14, pady=(4, 12))

        ctk.CTkLabel(
            right_col,
            text="PROVISION EXTERNAL USB DRIVE:\nWrites classified.key & registers serial",
            font=get_mono_font(10, "normal"),
            text_color=COLOR_TEXT_MUTED,
            justify="left",
        ).pack(anchor="w", padx=14, pady=(6, 4))

        self.btn_provision_usb = ctk.CTkButton(
            right_col,
            text="⚡ PROVISION USB DRIVE FOLDER...",
            font=get_mono_font(11, "bold"),
            height=32,
            fg_color=COLOR_SURFACE,
            border_color=COLOR_BORDER,
            border_width=1,
            hover_color=COLOR_BORDER,
            command=self._provision_usb_dialog,
        )
        self.btn_provision_usb.pack(fill="x", padx=14, pady=(0, 14))

        self.btn_next_step2 = ctk.CTkButton(
            right_col,
            text="PROCEED TO STAGE 2 (BIOMETRICS) ➔",
            font=get_mono_font(12, "bold"),
            height=42,
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            state="disabled",
            command=lambda: self.show_step(2),
        )
        self.btn_next_step2.pack(side="bottom", fill="x", padx=14, pady=14)

    def _on_toggle_dev_dongle(self) -> None:
        self.auth_gate.dev_dongle_enabled = bool(self.dev_dongle_var.get())
        state_str = "ENABLED" if self.auth_gate.dev_dongle_enabled else "DISABLED"
        self.log(f"Virtual Hardware Token (dongle_sample/classified.key) {state_str}.", "INFO")
        self.refresh_usb_status()

    def _provision_usb_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("SETUP NEW FORENSIC USB DONGLE & OPERATOR ENROLLMENT")
        dialog.geometry("520x680")
        dialog.minsize(480, 620)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text="PROVISION NEW OPERATOR USB DONGLE",
            font=get_mono_font(13, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 2))

        ctk.CTkLabel(
            dialog,
            text="Pendaftaran USB token fisik, biometrik wajah, dan sandi kustodian.",
            font=get_mono_font(11),
            text_color=COLOR_TEXT_MUTED,
        ).pack(anchor="w", padx=20, pady=(0, 10))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # 1. Target Mount Path
        ctk.CTkLabel(scroll, text="1. USB Flash Drive Mount Directory:", font=get_mono_font(11, "bold")).pack(anchor="w")
        path_row = ctk.CTkFrame(scroll, fg_color="transparent")
        path_row.pack(fill="x", pady=(2, 8))
        entry_path = ctk.CTkEntry(path_row, placeholder_text="Pilih folder root USB...", font=get_mono_font(11))
        entry_path.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def _browse():
            d = filedialog.askdirectory(title="Pilih Root Flash Drive USB", parent=dialog)
            if d:
                entry_path.delete(0, "end")
                entry_path.insert(0, d)

        ctk.CTkButton(path_row, text="📁 BROWSE", width=80, command=_browse, font=get_mono_font(11, "bold")).pack(side="right")

        # 2. Operator Name
        ctk.CTkLabel(scroll, text="2. Nama Operator / Penyidik:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_name = ctk.CTkEntry(scroll, placeholder_text="misal: Bintang Shada, S.Kom", font=get_mono_font(11))
        entry_name.pack(fill="x", pady=(2, 8))

        # 3. Badge ID
        ctk.CTkLabel(scroll, text="3. Badge ID / NIP:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_badge = ctk.CTkEntry(scroll, placeholder_text="misal: POL-FORENSIK-01", font=get_mono_font(11))
        entry_badge.pack(fill="x", pady=(2, 8))

        # 4. Password
        ctk.CTkLabel(scroll, text="4. Sandi Rahasia Custodian:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_pwd = ctk.CTkEntry(scroll, placeholder_text="Masukkan password kuat...", show="•", font=get_mono_font(11))
        entry_pwd.pack(fill="x", pady=(2, 10))

        # 5. Biometric Face Capture
        ctk.CTkLabel(scroll, text="5. Rekam Biometrik Wajah Operator (Wajib):", font=get_mono_font(11, "bold")).pack(anchor="w")
        
        cam_box = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6)
        cam_box.pack(fill="x", pady=(4, 8))

        cam_preview = ctk.CTkLabel(
            cam_box,
            text="[ KAMERA STANDBY ]\nKlik 'NYALAKAN KAMERA' untuk merekam wajah operator",
            font=get_mono_font(11, "bold"),
            text_color=COLOR_TEXT_MUTED,
            height=180,
        )
        cam_preview.pack(fill="x", padx=8, pady=8)

        bio_state = {
            "cap": None,
            "running": False,
            "after_id": None,
            "last_frame": None,
            "captured_vector": None,
            "ctk_img": None,
        }

        lbl_face_status = ctk.CTkLabel(
            scroll,
            text="⚠️ STATUS BIOMETRIK: BELUM DIAMBIL (WAJIB)",
            font=get_mono_font(11, "bold"),
            text_color=COLOR_AMBER,
        )
        lbl_face_status.pack(anchor="w", pady=(0, 6))

        def _stop_dialog_cam():
            bio_state["running"] = False
            if bio_state["after_id"]:
                try:
                    dialog.after_cancel(bio_state["after_id"])
                except Exception:
                    pass
                bio_state["after_id"] = None
            if bio_state["cap"] is not None:
                try:
                    bio_state["cap"].release()
                except Exception:
                    pass
                bio_state["cap"] = None
            try:
                if hasattr(cam_preview, "_label") and cam_preview._label is not None:
                    cam_preview._label.configure(image="")
            except Exception:
                pass
            bio_state["ctk_img"] = None

        def _poll_dialog_cam():
            if not bio_state["running"] or bio_state["cap"] is None:
                return
            ret, frame = bio_state["cap"].read()
            if not ret or frame is None:
                _stop_dialog_cam()
                return

            bio_state["last_frame"] = frame.copy()
            detected, ann, _, _ = self.auth_gate.detect_face_in_frame(frame)
            rgb = cv2.cvtColor(ann, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb)
            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(320, 180))
            bio_state["ctk_img"] = ctk_img
            cam_preview.configure(image=ctk_img, text="")
            bio_state["after_id"] = dialog.after(30, _poll_dialog_cam)

        def _start_dialog_cam():
            if not OPENCV_AVAILABLE or cv2 is None:
                lbl_face_status.configure(text="OpenCV tidak tersedia pada sistem!", text_color=COLOR_CRIMSON)
                return
            if bio_state["running"]:
                return
            try:
                bio_state["cap"] = cv2.VideoCapture(0)
                if not bio_state["cap"] or not bio_state["cap"].isOpened():
                    _stop_dialog_cam()
                    lbl_face_status.configure(text="Kamera tidak dapat diakses! Berikan izin kamera.", text_color=COLOR_CRIMSON)
                    return
                bio_state["running"] = True
                lbl_face_status.configure(text="◉ KAMERA AKTIF: Posisikan wajah di tengah...", text_color=COLOR_PRIMARY)
                _poll_dialog_cam()
            except Exception as exc:
                lbl_face_status.configure(text=f"Error kamera: {exc}", text_color=COLOR_CRIMSON)

        def _capture_dialog_face():
            if not bio_state["running"] or bio_state["last_frame"] is None:
                lbl_face_status.configure(text="Nyalakan kamera terlebih dahulu!", text_color=COLOR_CRIMSON)
                return
            detected, _, _, bbox = self.auth_gate.detect_face_in_frame(bio_state["last_frame"])
            if not detected or bbox[2] < 30 or bbox[3] < 30:
                lbl_face_status.configure(text="Wajah belum terdeteksi jelas! Dekatkan wajah.", text_color=COLOR_CRIMSON)
                return

            vec = self.auth_gate.extract_face_feature_vector(bio_state["last_frame"], bbox)
            if not vec:
                lbl_face_status.configure(text="Gagal mengekstrak vektor biometrik wajah!", text_color=COLOR_CRIMSON)
                return

            bio_state["captured_vector"] = vec
            lbl_face_status.configure(
                text=f"✓ WAJAH OPERATOR TERKUNCI & TERDAFTAR [{bbox[2]}x{bbox[3]}px]",
                text_color=COLOR_EMERALD,
            )
            _stop_dialog_cam()
            cam_preview.configure(text="[ FOTO WAJAH BERHASIL DIAMBIL & TERKUNCI ]", text_color=COLOR_EMERALD)

        cam_btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        cam_btn_row.pack(fill="x", pady=(0, 10))
        ctk.CTkButton(
            cam_btn_row,
            text="◉ NYALAKAN KAMERA",
            width=140,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=_start_dialog_cam,
            font=get_mono_font(11, "bold"),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            cam_btn_row,
            text="📸 AMBIL FOTO WAJAH",
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=_capture_dialog_face,
            font=get_mono_font(11, "bold"),
        ).pack(side="right", fill="x", expand=True)

        lbl_status = ctk.CTkLabel(dialog, text="", font=get_mono_font(11), text_color=COLOR_AMBER)
        lbl_status.pack(padx=20, pady=(2, 6))

        def _execute_provision():
            mount = entry_path.get().strip()
            name = entry_name.get().strip()
            badge = entry_badge.get().strip()
            pwd = entry_pwd.get().strip()
            face_vec = bio_state.get("captured_vector")

            if not mount or not Path(mount).exists():
                lbl_status.configure(text="Pilih direktori mount USB yang valid!", text_color=COLOR_CRIMSON)
                return
            if not name or not badge or not pwd:
                lbl_status.configure(text="Semua kolom nama, badge, dan sandi wajib diisi!", text_color=COLOR_CRIMSON)
                return
            if len(pwd) < 6:
                lbl_status.configure(text="Sandi minimal 6 karakter demi keamanan!", text_color=COLOR_CRIMSON)
                return
            if not face_vec:
                lbl_status.configure(text="Wajah operator wajib direkam sebelum mendaftarkan USB!", text_color=COLOR_CRIMSON)
                return

            _stop_dialog_cam()
            ok, msg = self.auth_gate.provision_usb_drive(
                mount_path=mount,
                operator_name=name,
                badge_id=badge,
                password=pwd,
                face_profile_hash=face_vec,
            )
            self.log(msg, "SUCCESS" if ok else "ERROR")
            if ok:
                dialog.destroy()
                self.refresh_usb_status()
            else:
                lbl_status.configure(text=msg, text_color=COLOR_CRIMSON)

        def _on_close():
            _stop_dialog_cam()
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", _on_close)

        btn_row = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(4, 14))
        ctk.CTkButton(
            btn_row,
            text="BATAL",
            width=90,
            fg_color=COLOR_SURFACE,
            hover_color=COLOR_BORDER,
            command=_on_close,
            font=get_mono_font(11, "bold"),
        ).pack(side="left")
        ctk.CTkButton(
            btn_row,
            text="💾 BUAT DONGLE & DAFTARKAN",
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=_execute_provision,
            font=get_mono_font(11, "bold"),
        ).pack(side="right", fill="x", expand=True, padx=(10, 0))

    def refresh_usb_status(self) -> None:
        status = self.auth_gate.scan_hardware_dongle()
        bus_devices = self.auth_gate.get_os_usb_serials()
        mounts = self.auth_gate.get_removable_mounts()

        lines = [
            f"STATUS         : {'AUTHORIZED & ACTIVE' if status.authorized else 'LOCKED / UNAUTHORIZED'}",
            f"SERIAL NUMBER  : {status.serial_number}",
            f"MOUNT POINT    : {status.mount_point}",
            f"TOKEN PATH     : {status.token_file_path}",
            f"CUSTODIAN NAME : {status.operator_name}",
            f"BADGE ID       : {status.badge_id}",
            f"MODE           : {'VIRTUAL DEV DONGLE' if status.is_dev_fallback else 'PHYSICAL USB HARDWARE'}",
            "-" * 58,
            f"DETECTED USB BUS DEVICES ({len(bus_devices)}):",
        ]
        if bus_devices:
            for d in bus_devices:
                lines.append(f"  • {d.get('name')} | SN: {d.get('serial')}")
        else:
            lines.append("  • [No Physical USB Storage Serials on Bus]")

        lines.append(f"REMOVABLE MOUNTS ({len(mounts)}):")
        if mounts:
            for m in mounts:
                lines.append(f"  • {m}")
        else:
            lines.append("  • [No External Volumes Mounted]")

        lines.append("-" * 58)
        lines.append(f"DIAGNOSTIC     : {status.message}")

        self.usb_details_box.configure(state="normal")
        self.usb_details_box.delete("1.0", "end")
        self.usb_details_box.insert("1.0", "\n".join(lines))
        self.usb_details_box.configure(state="disabled")

        if status.connected and status.authorized:
            self.verified_dongle = status
            self.lbl_usb_status.set_status(f"TOKEN VERIFIED: {status.serial_number}", "SUCCESS")
            self.badge_step1.set_status("STAGE 1: USB VERIFIED", "SUCCESS")
            self.btn_next_step2.configure(state="normal")
            self.log(f"Stage 1 Verified: {status.serial_number} ({status.operator_name})", "SUCCESS")
        else:
            self.verified_dongle = None
            self.lbl_usb_status.set_status("HARDWARE TOKEN NOT VERIFIED", "DANGER")
            self.badge_step1.set_status("STAGE 1: USB REQUIRED", "WARN")
            self.btn_next_step2.configure(state="disabled")
            self.log(status.message, "WARN")

    # =========================================================================
    # SCREEN 2: OPENCV HAAR CASCADE FACE BIOMETRIC SCANNING
    # =========================================================================
    def _build_screen2(self) -> None:
        self.screen2 = HUDCard(
            self.screen_container,
            title="SCREEN 2 // BIOMETRIC FACE VERIFICATION (OPENCV HAAR CASCADE)",
            subtitle="haarcascade_frontalface_default.xml + Hardware Fallback Mode",
        )

        body = ctk.CTkFrame(self.screen2, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=10)

        # Left: Camera Viewport
        cam_frame = ctk.CTkFrame(
            body, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6
        )
        cam_frame.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=4)

        self.camera_label = ctk.CTkLabel(
            cam_frame,
            text="[ CAMERA VIEWPORT STANDBY ]\nClick 'START WEBCAM SCAN' or use 'BIOMETRIC BYPASS (NO WEBCAM)'",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_MUTED,
            width=460,
            height=270,
        )
        self.camera_label.pack(fill="both", expand=True, padx=10, pady=10)

        # Right: Controls & Progress
        ctrl_frame = ctk.CTkFrame(
            body, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6, width=350
        )
        ctrl_frame.pack(side="right", fill="y", padx=(10, 0), pady=4)
        ctrl_frame.pack_propagate(False)

        ctk.CTkLabel(
            ctrl_frame,
            text="BIOMETRIC TELEMETRY",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self.lbl_bio_status = StatusBadge(ctrl_frame, text="AWAITING BIOMETRIC LOCK", status="WARN")
        self.lbl_bio_status.pack(anchor="w", padx=14, pady=(0, 10))

        self.bio_progress = ctk.CTkProgressBar(
            ctrl_frame, progress_color=COLOR_EMERALD, fg_color=COLOR_BASE, height=12
        )
        self.bio_progress.pack(fill="x", padx=14, pady=(0, 6))
        self.bio_progress.set(0.0)

        self.lbl_bio_progress_text = ctk.CTkLabel(
            ctrl_frame,
            text="Consecutive Face Lock: 0 / 10 frames",
            font=get_mono_font(11, "normal"),
            text_color=COLOR_TEXT_MUTED,
        )
        self.lbl_bio_progress_text.pack(anchor="w", padx=14, pady=(0, 12))

        self.btn_start_cam = ctk.CTkButton(
            ctrl_frame,
            text="◉ START WEBCAM HAAR SCAN",
            font=get_mono_font(12, "bold"),
            height=36,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self.start_webcam_scan,
        )
        self.btn_start_cam.pack(fill="x", padx=14, pady=(0, 8))

        nav_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        nav_row.pack(side="bottom", fill="x", padx=14, pady=14)

        ctk.CTkButton(
            nav_row,
            text="⬅ STAGE 1",
            width=95,
            height=38,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_SURFACE,
            hover_color=COLOR_BORDER,
            command=lambda: self.show_step(1),
        ).pack(side="left")

        self.btn_next_step3 = ctk.CTkButton(
            nav_row,
            text="STAGE 3 (PASSWORD) ➔",
            height=38,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            state="disabled",
            command=lambda: self.show_step(3),
        )
        self.btn_next_step3.pack(side="right", fill="x", expand=True, padx=(8, 0))

    def start_webcam_scan(self) -> None:
        if not OPENCV_AVAILABLE or cv2 is None:
            self.log("OpenCV tidak tersedia pada sistem.", "ERROR")
            self.lbl_bio_status.set_status("OPENCV NOT INSTALLED", "DANGER")
            return

        if self._camera_running:
            return

        try:
            self._cap = cv2.VideoCapture(0)
            if not self._cap or not self._cap.isOpened():
                self.stop_webcam()
                self._clear_camera_label_image()
                self.camera_label.configure(
                    text="[ WEBCAM UNAVAILABLE OR PERMISSION DENIED ]\nmacOS/OS blocked camera access for Terminal.\nPlease grant camera permission in System Settings.",
                    text_color=COLOR_CRIMSON,
                )
                self.log(
                    "Webcam fisik tidak terdeteksi atau izin kamera belum diberikan ke Terminal.",
                    "ERROR",
                )
                self.lbl_bio_status.set_status("WEBCAM BLOCKED", "DANGER")
                return

            self._camera_running = True
            self._face_lock_counter = 0
            self.lbl_bio_status.set_status("SCANNING FACE VIA BIOMETRIC SENSOR...", "INFO")
            self.log("Biometric Face Scanner aktif.", "INFO")
            self._poll_webcam_frame()
        except Exception as exc:
            self.log(f"Gagal membuka kamera: {exc}.", "ERROR")
            self.lbl_bio_status.set_status("CAMERA ERROR", "DANGER")

    def _poll_webcam_frame(self) -> None:
        if not self._camera_running or self._cap is None:
            return

        ret, frame = self._cap.read()
        if not ret or frame is None:
            self.stop_webcam()
            self.lbl_bio_status.set_status("CAMERA STREAM INTERRUPTED", "WARN")
            return

        detected, annotated_bgr, _, bbox = self.auth_gate.detect_face_in_frame(frame)
        self._last_raw_frame = frame.copy()
        self._last_bbox = bbox

        rgb = cv2.cvtColor(annotated_bgr, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(rgb)
        ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(440, 260))
        self._cam_ctk_image = ctk_img
        self.camera_label.configure(image=ctk_img, text="")

        # Check face match against enrolled profile
        is_matched = False
        similarity_pct = 0.0
        face_status_msg = "SEARCHING FACE..."
        face_status_mode = "WARN"

        if detected and self.verified_dongle:
            is_masked, _ = self.auth_gate.is_face_masked(frame, bbox)
            if is_masked:
                is_matched = False
                face_status_msg = "⚠️ MASKER TERDETEKSI! HARAP LEPAS MASKER"
                face_status_mode = "DANGER"
            else:
                rec = self.auth_gate.db_manager.get_dongle(self.verified_dongle.serial_number) or {}
                stored_hash = str(rec.get("face_profile_hash") or "").strip()

                if not stored_hash or stored_hash in ("EMPTY", "NONE", "") or len(stored_hash) < 30:
                    is_matched = False
                    face_status_msg = "PROFIL WAJAH BELUM TERDAFTAR PADA TOKEN!"
                    face_status_mode = "DANGER"
                else:
                    cand_vec = self.auth_gate.extract_face_feature_vector(frame, bbox)
                    if cand_vec:
                        is_matched, similarity_pct = self.auth_gate.compare_face_feature(cand_vec, stored_hash)
                        if is_matched:
                            face_status_msg = f"OPERATOR TERVERIFIKASI ({similarity_pct:.0f}%)"
                            face_status_mode = "INFO"
                        else:
                            face_status_msg = f"WAJAH TIDAK COCOK / UNAUTHORIZED ({similarity_pct:.0f}%)"
                            face_status_mode = "DANGER"
        elif not detected:
            face_status_msg = "SEARCHING FACE... HADAPKAN KE KAMERA"
            face_status_mode = "WARN"

        if detected and is_matched:
            self._face_lock_counter = min(self._required_face_frames, self._face_lock_counter + 1)
            self.lbl_bio_status.set_status(face_status_msg, face_status_mode)
        else:
            self._face_lock_counter = max(0, self._face_lock_counter - 1)
            self.lbl_bio_status.set_status(face_status_msg, face_status_mode)

        ratio = self._face_lock_counter / float(self._required_face_frames)
        self.bio_progress.set(ratio)
        self.lbl_bio_progress_text.configure(
            text=f"Consecutive Face Lock: {self._face_lock_counter} / {self._required_face_frames} frames"
        )

        if self._face_lock_counter >= self._required_face_frames:
            self.biometric_verified = True
            self.stop_webcam()
            self.lbl_bio_status.set_status("BIOMETRIC FACE VERIFIED", "SUCCESS")
            self.badge_step2.set_status("STAGE 2: FACE VERIFIED", "SUCCESS")
            self.btn_next_step3.configure(state="normal")
            self.log(f"Biometrik Wajah Terverifikasi (Match: {similarity_pct:.1f}%).", "SUCCESS")
            return

        self.after(25, self._poll_webcam_frame)

    def stop_webcam(self) -> None:
        self._camera_running = False
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

    def _clear_camera_label_image(self) -> None:
        """
        Safely detaches any CTkImage from camera_label without triggering
        CustomTkinter's TclError ('pyimage doesn't exist') when image=None is passed.
        """
        try:
            if isinstance(getattr(self.camera_label, "_image", None), ctk.CTkImage):
                self.camera_label._image.remove_configure_callback(self.camera_label._update_image)
            self.camera_label._image = None
            if hasattr(self.camera_label, "_label") and self.camera_label._label is not None:
                self.camera_label._label.configure(image="")
        except Exception:
            pass
        self._cam_ctk_image = None



    # =========================================================================
    # SCREEN 3: SALTED SHA-256 PASSWORD HASH AUTHENTICATION
    # =========================================================================
    def _build_screen3(self) -> None:
        self.screen3 = HUDCard(
            self.screen_container,
            title="SCREEN 3 // SALTED SHA-256 CRYPTOGRAPHIC PASSWORD GATE",
            subtitle="Verification: SHA256(16_byte_random_salt + UTF8_password)",
        )

        body = ctk.CTkFrame(self.screen3, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=10)

        card = ctk.CTkFrame(
            body, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6
        )
        card.pack(fill="both", expand=True, pady=4)

        ctk.CTkLabel(
            card,
            text="ENTER CUSTODIAN MASTER PASSPHRASE",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", padx=18, pady=(14, 6))

        entry_row = ctk.CTkFrame(card, fg_color="transparent")
        entry_row.pack(fill="x", padx=18, pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(
            entry_row,
            placeholder_text="Masukkan Sandi Custodian...",
            show="•",
            height=40,
            font=get_mono_font(13, "bold"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.pwd_entry.bind("<Return>", lambda _e: self._verify_stage3_password())

        self.btn_unlock_vault = ctk.CTkButton(
            entry_row,
            text="🔓 VERIFY HASH & UNLOCK VAULT",
            height=40,
            width=250,
            font=get_mono_font(12, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self._verify_stage3_password,
        )
        self.btn_unlock_vault.pack(side="right")

        self.lbl_pwd_status = StatusBadge(card, text="READY FOR SALTED SHA-256 CHECK", status="INFO")
        self.lbl_pwd_status.pack(anchor="w", padx=18, pady=(0, 8))

        self.hash_inspector = ctk.CTkTextbox(
            card,
            height=130,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(11, "normal"),
            text_color=COLOR_TEXT_MUTED,
        )
        self.hash_inspector.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.hash_inspector.configure(state="disabled")

        bottom_nav = ctk.CTkFrame(card, fg_color="transparent")
        bottom_nav.pack(fill="x", padx=18, pady=(0, 12))

        ctk.CTkButton(
            bottom_nav,
            text="⬅ BACK TO STAGE 2 (BIOMETRICS)",
            height=32,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_SURFACE,
            hover_color=COLOR_BORDER,
            command=lambda: self.show_step(2),
        ).pack(side="left")

    def _populate_stage3_telemetry(self) -> None:
        if not self.verified_dongle:
            return
        rec = self.auth_gate.db_manager.get_dongle(self.verified_dongle.serial_number)
        if not rec:
            return

        info = (
            f"BOUND HARDWARE SERIAL : {rec.get('serial_number')}\n"
            f"OPERATOR              : {rec.get('operator_name')} ({rec.get('badge_id')})\n"
            f"STORED 16-BYTE SALT   : {rec.get('password_salt')}\n"
            f"STORED SHA-256 DIGEST : {rec.get('password_hash')}\n"
            f"FORMULA               : SHA256(bytes.fromhex(salt) + password.encode('utf-8'))"
        )
        self.hash_inspector.configure(state="normal")
        self.hash_inspector.delete("1.0", "end")
        self.hash_inspector.insert("1.0", info)
        self.hash_inspector.configure(state="disabled")

    def _verify_stage3_password(self) -> None:
        # Re-verify hardware token right before unlocking
        live_dongle = self.auth_gate.scan_hardware_dongle()
        if not live_dongle.connected or not live_dongle.authorized:
            self.lbl_pwd_status.set_status("USB DONGLE MISSING! RETURN TO STAGE 1", "DANGER")
            self.log("Gagal membuka vault: USB Dongle telah dicabut!", "CRITICAL")
            self.show_step(1)
            return

        candidate = self.pwd_entry.get()
        is_valid, computed_hash, msg = self.auth_gate.verify_password(
            live_dongle.serial_number, candidate
        )

        rec = self.auth_gate.db_manager.get_dongle(live_dongle.serial_number) or {}
        inspector_text = (
            f"BOUND HARDWARE SERIAL : {live_dongle.serial_number}\n"
            f"STORED 16-BYTE SALT   : {rec.get('password_salt', '')}\n"
            f"EXPECTED SHA-256 HASH : {rec.get('password_hash', '')}\n"
            f"COMPUTED SHA-256 HASH : {computed_hash}\n"
            f"RESULT                : {msg}"
        )
        self.hash_inspector.configure(state="normal")
        self.hash_inspector.delete("1.0", "end")
        self.hash_inspector.insert("1.0", inspector_text)
        self.hash_inspector.configure(state="disabled")

        if is_valid:
            self.lbl_pwd_status.set_status("HASH MATCHED - UNLOCKING VAULT", "SUCCESS")
            self.badge_step3.set_status("STAGE 3: HASH VERIFIED", "SUCCESS")
            self.on_authenticated(live_dongle)
        else:
            self.lbl_pwd_status.set_status("INVALID PASSWORD HASH", "DANGER")

    # =========================================================================
    # NAVIGATION & RESET
    # =========================================================================
    def show_step(self, step: int) -> None:
        self.stop_webcam()
        self.current_step = step
        for frame in (self.screen1, self.screen2, self.screen3):
            frame.pack_forget()

        if step == 1:
            self.screen1.pack(fill="both", expand=True)
            self.refresh_usb_status()
        elif step == 2:
            self.screen2.pack(fill="both", expand=True)
        elif step == 3:
            self.screen3.pack(fill="both", expand=True)
            self._populate_stage3_telemetry()

    def reset_for_lockdown(self, reason: str = "") -> None:
        """Called when the Hardware Kill-Switch or manual Lock triggers. Clears all credentials."""
        self.stop_webcam()
        self.verified_dongle = None
        self.biometric_verified = False
        self._face_lock_counter = 0
        self._last_raw_frame = None

        # Reset Face UI & Camera
        self._clear_camera_label_image()
        self.bio_progress.set(0.0)
        self.lbl_bio_progress_text.configure(text="Consecutive Face Lock: 0 / 6 frames")
        self.lbl_bio_status.set_status("AWAITING BIOMETRIC LOCK", "WARN")
        self.btn_next_step3.configure(state="disabled")

        # Reset Password UI
        self.pwd_entry.delete(0, "end")
        self.lbl_pwd_status.set_status("READY FOR SALTED SHA-256 CHECK", "INFO")
        self.hash_inspector.configure(state="normal")
        self.hash_inspector.delete("1.0", "end")
        self.hash_inspector.configure(state="disabled")

        # Reset USB & Badges
        self.dev_dongle_var.set(self.auth_gate.dev_dongle_enabled)
        self.badge_step1.set_status("STAGE 1: USB LOCKED", "DANGER")
        self.badge_step2.set_status("STAGE 2: BIOMETRIC RESET", "WARN")
        self.badge_step3.set_status("STAGE 3: SESSION LOCKED", "DANGER")
        self.show_step(1)
        if reason:
            self.lbl_usb_status.set_status("KILL-SWITCH AUTO-LOCK TRIGGERED", "DANGER")

