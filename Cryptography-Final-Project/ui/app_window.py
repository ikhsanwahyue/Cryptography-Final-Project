"""
Main Application Window, Theme Manager, and Hardware Kill-Switch Listener
for LexVault (`ui/app_window.py`).
"""

import os
from typing import Optional

import customtkinter as ctk

from core.auth_gate import AuthGate, DongleStatus
from core.local_blockchain import LocalBlockchain
from core.web3_sync import Web3SyncWorker
from database.db_manager import DatabaseManager
from ui.components import (
    COLOR_BASE,
    COLOR_BORDER,
    COLOR_CRIMSON,
    COLOR_SURFACE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    ForensicLogViewer,
    StatusBadge,
    get_mono_font,
)
from ui.frames_auth import AuthWizardFrame
from ui.frames_crypto import ForensicWorkspaceTabs


class LexVaultApp(ctk.CTk):
    """
    Root CustomTkinter Application Container for LexVault:
    Forensic Evidence Custody & Anti-Tamper Archival System (ISO/IEC 27037).
    """

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("LEXVAULT // Forensic Evidence Custody & Anti-Tamper Archival System (ISO/IEC 27037)")
        self.geometry("1280x860")
        self.minsize(1100, 760)
        self.configure(fg_color=COLOR_BASE)

        # Build UI shell first so logger is ready for core subsystems
        self._build_top_header()
        self.main_stage = ctk.CTkFrame(self, fg_color=COLOR_BASE)
        self.main_stage.pack(fill="both", expand=True)

        self.log_viewer = ForensicLogViewer(self, height=120)
        self.log_viewer.pack(fill="x", side="bottom", padx=18, pady=(4, 14))

        # Initialize Core Subsystems
        self.db_manager = DatabaseManager(logger_callback=self.threadsafe_log)
        self.blockchain = LocalBlockchain(db_manager=self.db_manager)
        self.web3_worker = Web3SyncWorker(logger_callback=self.threadsafe_log)
        self.auth_gate = AuthGate(
            db_manager=self.db_manager,
            poll_interval=1.5,
            logger_callback=self.threadsafe_log,
        )

        # Default dev dongle toggle is OFF (requires physical USB unless manually toggled ON)
        self.auth_gate.dev_dongle_enabled = False

        # self._update_db_badge()

        # Build Views
        self.auth_frame = AuthWizardFrame(
            self.main_stage,
            auth_gate=self.auth_gate,
            on_authenticated=self._on_session_authenticated,
            log_callback=self.threadsafe_log,
        )
        self.workspace_frame: Optional[ForensicWorkspaceTabs] = None

        # Register & Start Hardware Kill-Switch Daemon (1.5s USB polling)
        self.auth_gate.register_kill_switch_callback(self._on_hardware_kill_switch)
        self.auth_gate.start_kill_switch_daemon()

        # Start in Locked Auth Gate
        self.auth_frame.pack(fill="both", expand=True)
        self.auth_frame.refresh_usb_status()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_top_header(self) -> None:
        self.header_bar = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            border_color=COLOR_BORDER,
            border_width=1,
            corner_radius=0,
            height=62,
        )
        self.header_bar.pack(fill="x", side="top")
        self.header_bar.pack_propagate(False)

        left_box = ctk.CTkFrame(self.header_bar, fg_color="transparent")
        left_box.pack(side="left", padx=18, pady=8)

        ctk.CTkLabel(
            left_box,
            text="LEXVAULT // FORENSIC CUSTODY TERMINAL",
            font=get_mono_font(15, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        # ctk.CTkLabel(
        #     left_box,
        #     text="ISO/IEC 27037 STANDARD | SUPER-CRYPTO | ChaCha20 | LSB STEGO | HYBRID BLOCKCHAIN",
        #     font=get_mono_font(10, "normal"),
        #     text_color=COLOR_TEXT_MUTED,
        # ).pack(anchor="w")

        right_box = ctk.CTkFrame(self.header_bar, fg_color="transparent")
        right_box.pack(side="right", padx=18, pady=10)

        # self.badge_usb = StatusBadge(right_box, text="USB SESSION: LOCKED", status="LOCKED")
        # self.badge_usb.pack(side="left", padx=6)

        # self.badge_db = StatusBadge(right_box, text="DB: INITIALIZING", status="INFO")
        # self.badge_db.pack(side="left", padx=6)

        # self.badge_chain = StatusBadge(right_box, text="LEDGER: VERIFIED", status="SUCCESS")
        # self.badge_chain.pack(side="left", padx=6)

        self.btn_lock_session = ctk.CTkButton(
            right_box,
            text="LOCK VAULT",
            width=125,
            height=30,
            font=get_mono_font(11, "bold"),
            fg_color="#450A0A",
            hover_color="#7F1D1D",
            text_color=COLOR_CRIMSON,
            border_color=COLOR_CRIMSON,
            border_width=1,
            state="disabled",
            command=lambda: self._lock_session("Manual operator lock triggered."),
        )
        self.btn_lock_session.pack(side="left", padx=(10, 0))

    def _update_db_badge(self) -> None:
        if hasattr(self, "badge_db"):
            if self.db_manager.cloud_online:
                self.badge_db.set_status("DB: SUPABASE + SQLITE", "SUCCESS")
            else:
                self.badge_db.set_status("DB: SQLITE FALLBACK", "WARN")

    def threadsafe_log(self, message: str, level: str = "INFO") -> None:
        try:
            self.after(0, lambda: self.log_viewer.log(message, level))
        except Exception:
            pass

    def _on_session_authenticated(self, dongle: DongleStatus) -> None:
        self.auth_frame.pack_forget()

        if self.workspace_frame is None:
            self.workspace_frame = ForensicWorkspaceTabs(
                self.main_stage,
                db_manager=self.db_manager,
                blockchain=self.blockchain,
                web3_worker=self.web3_worker,
                auth_gate=self.auth_gate,
                active_dongle=dongle,
                log_callback=self.threadsafe_log,
                on_chain_status_change=self._on_chain_integrity_updated,
            )
        else:
            self.workspace_frame.active_dongle = dongle

        self.workspace_frame.pack(fill="both", expand=True)
        self.workspace_frame.refresh_audit_ledger()

        if hasattr(self, "badge_usb"):
            self.badge_usb.set_status(f"USB UNLOCKED [{dongle.serial_number}]", "UNLOCKED")
        self.btn_lock_session.configure(state="normal")
        self.threadsafe_log(
            f"Sesi Custody Aktif untuk {dongle.operator_name} ({dongle.badge_id}). "
            f"Kill-Switch memantau dongle setiap {self.auth_gate.poll_interval:.1f} detik.",
            "SUCCESS",
        )

    def _on_chain_integrity_updated(self, is_valid: bool) -> None:
        if hasattr(self, "badge_chain"):
            if is_valid:
                self.badge_chain.set_status("LEDGER: VERIFIED", "SUCCESS")
            else:
                self.badge_chain.set_status("LEDGER: TAMPER BREACH!", "DANGER")

    def _on_hardware_kill_switch(self, reason: str) -> None:
        """Invoked from the background USB polling daemon thread."""
        self.after(0, lambda: self._lock_session(reason))

    def _lock_session(self, reason: str) -> None:
        self.auth_gate.session_unlocked = False
        self.auth_gate.active_dongle = None
        if self.workspace_frame is not None:
            # Stop any running camera in Tab 5 if active
            try:
                self.workspace_frame._tab5_stop_cam()
            except Exception:
                pass
            self.workspace_frame.active_dongle = None
            self.workspace_frame.pack_forget()

        # self.badge_usb.set_status("USB SESSION: LOCKED", "LOCKED")
        self.btn_lock_session.configure(state="disabled")
        self.auth_frame.reset_for_lockdown(reason)
        self.auth_frame.pack(fill="both", expand=True)
        self.threadsafe_log(reason, "CRITICAL")

    def _on_close(self) -> None:
        self.auth_gate.stop_kill_switch_daemon()
        self.auth_frame.stop_webcam()
        self.destroy()

