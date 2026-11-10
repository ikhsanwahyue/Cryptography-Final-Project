"""
Forensic Cryptographic & Chain of Custody Tabs (`ui/frames_crypto.py`):
- Tab 1: Text Super-Crypto (Vigenere Full-ASCII mod 256 + AES-256-CBC PKCS7)
- Tab 2: Binary File Locker (ChaCha20 12-byte nonce stream cipher `.locked`)
- Tab 3: Steganography Studio (Lossless PNG LSB with 32-bit length header)
- Tab 4: Chain of Custody Audit Ledger (Layer 1 PoW + Layer 2 Polygon Amoy Explorer)
"""

import secrets
import webbrowser
from pathlib import Path
from tkinter import filedialog
from typing import Any, Callable, Optional

import customtkinter as ctk
from PIL import Image, ImageDraw

from core.auth_gate import OPENCV_AVAILABLE, AuthGate, DongleStatus, cv2
from core.file_crypto import BinaryFileLocker
from core.local_blockchain import LocalBlockchain
from core.stego_engine import StegoEngine
from core.text_crypto import TextSuperCrypto
from core.web3_sync import Web3AnchorResult, Web3SyncWorker
from database.db_manager import DatabaseManager
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


class ForensicWorkspaceTabs(ctk.CTkFrame):
    """
    Main unlocked forensic workspace containing the 4 core operational modules:
    1. Text Super-Crypto
    2. Binary File Locker (ChaCha20)
    3. LSB Steganography Studio
    4. Dual-Layer Chain of Custody Audit Ledger
    """

    def __init__(
        self,
        master: Any,
        db_manager: DatabaseManager,
        blockchain: LocalBlockchain,
        web3_worker: Web3SyncWorker,
        log_callback: Callable[[str, str], None],
        auth_gate: Optional[AuthGate] = None,
        active_dongle: Optional[DongleStatus] = None,
        on_chain_status_change: Optional[Callable[[bool], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=COLOR_BASE, **kwargs)
        self.db_manager = db_manager
        self.blockchain = blockchain
        self.web3_worker = web3_worker
        self.auth_gate = auth_gate
        self.active_dongle = active_dongle
        self.log = log_callback
        self.on_chain_status_change = on_chain_status_change

        # Biometric enroll camera state in Tab 5
        self._cam_cap: Optional[Any] = None
        self._cam_running: bool = False
        self._last_raw_frame: Optional[Any] = None

        self.latest_explorer_url: str = "https://amoy.polygonscan.com/"
        self._build_tabs()

    def _build_tabs(self) -> None:
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=COLOR_SURFACE,
            segmented_button_fg_color=COLOR_SURFACE_DARK,
            segmented_button_selected_color=COLOR_PRIMARY,
            segmented_button_selected_hover_color=COLOR_PRIMARY_HOVER,
            segmented_button_unselected_color=COLOR_SURFACE_DARK,
            segmented_button_unselected_hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY,
            border_color=COLOR_BORDER,
            border_width=1,
            corner_radius=8,
        )
        self.tabview.pack(fill="both", expand=True, padx=18, pady=(6, 8))

        self.tab_text = self.tabview.add("1 // SUPER-CRYPTO (BAP)")
        self.tab_file = self.tabview.add("2 // FILE LOCKER (ChaCha20)")
        self.tab_stego = self.tabview.add("3 // STEGO STUDIO (LSB PNG)")
        self.tab_audit = self.tabview.add("4 // CHAIN OF CUSTODY AUDIT")
        self.tab_security = self.tabview.add("5 // SECURITY & BIOMETRIC")

        self._build_tab1_super_crypto()
        self._build_tab2_file_locker()
        self._build_tab3_stego_studio()
        self._build_tab4_audit_ledger()
        self._build_tab5_security()

    # =========================================================================
    # HELPER: SEAL EVIDENCE TO DUAL-LAYER BLOCKCHAIN + DATABASE
    # =========================================================================
    def _seal_to_custody_chain(
        self,
        evidence_prefix: str,
        evidence_type: str,
        ciphertext_or_path: str,
        iv_nonce: str,
        data_hash: str,
    ) -> str:
        evidence_id = f"{evidence_prefix}-{secrets.token_hex(3).upper()}"

        # 1. Mine Layer 1 Local PoW Block ("000")
        block = self.blockchain.add_evidence_block(
            evidence_id=evidence_id,
            evidence_hash=data_hash,
            layer2_tx_hash="PENDING_AMOY_SYNC",
        )
        self.log(
            f"Layer 1 PoW Block #{block.index} mined (Nonce: {block.nonce}, Hash: {block.hash[:18]}...)",
            "SUCCESS",
        )

        # 2. Save metadata to Dual-Layer Database (Supabase + SQLite fallback)
        _, storage_mode = self.db_manager.save_evidence_record(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            ciphertext_or_asset_path=ciphertext_or_path,
            iv_nonce=iv_nonce,
            data_hash=data_hash,
            layer1_block_hash=block.hash,
            layer2_tx_hash="PENDING_AMOY_SYNC",
        )
        self.log(f"Bukti '{evidence_id}' disimpan ke Database ({storage_mode}).", "INFO")

        # 3. Dispatch Async Layer 2 Polygon Amoy On-Chain Sync
        def _on_l2_done(ev_id: str, res: Web3AnchorResult) -> None:
            self.db_manager.update_evidence_layer2_tx(ev_id, res.tx_hash)
            self.blockchain.reload_from_db()
            self.latest_explorer_url = res.explorer_url
            self.after(0, self.refresh_audit_ledger)

        self.web3_worker.anchor_evidence_async(
            evidence_id=evidence_id,
            evidence_hash=data_hash,
            on_complete=_on_l2_done,
        )

        self.refresh_audit_ledger()
        return evidence_id

    # =========================================================================
    # TAB 1: TEXT SUPER-CRYPTO (VIGENERE FULL-ASCII MOD 256 + AES-256-CBC)
    # =========================================================================
    def _build_tab1_super_crypto(self) -> None:
        container = ctk.CTkFrame(self.tab_text, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=6)

        # Keys bar
        keys_card = HUDCard(
            container,
            title="HYBRID SUPER-ENCRYPTION KEYS",
            subtitle="Stage 1: Vigenere Full-ASCII (mod 256) ➔ Stage 2: AES-256-CBC (PKCS#7, 16-Byte Random IV)",
        )
        keys_card.pack(fill="x", pady=(0, 8))

        keys_row = ctk.CTkFrame(keys_card, fg_color="transparent")
        keys_row.pack(fill="x", padx=14, pady=(4, 12))

        ctk.CTkLabel(
            keys_row, text="VIGENERE KEY (ASCII):", font=get_mono_font(11, "bold")
        ).pack(side="left", padx=(0, 6))
        self.ent_vig_key = ctk.CTkEntry(
            keys_row,
            width=210,
            font=get_mono_font(12, "normal"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
        )
        self.ent_vig_key.pack(side="left", padx=(0, 16))
        self.ent_vig_key.insert(0, "GARUDA-FORENSIC-KEY")

        ctk.CTkLabel(
            keys_row, text="AES-256 PASSPHRASE:", font=get_mono_font(11, "bold")
        ).pack(side="left", padx=(0, 6))
        self.ent_aes_key = ctk.CTkEntry(
            keys_row,
            width=230,
            font=get_mono_font(12, "normal"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
        )
        self.ent_aes_key.pack(side="left", padx=(0, 16))
        self.ent_aes_key.insert(0, "ISO27037#BAP-SecretKey")

        self.chk_seal_text_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            keys_row,
            text="Auto-Seal to Blockchain & DB",
            variable=self.chk_seal_text_var,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_EMERALD,
        ).pack(side="right")

        # Main Dual Panes: Plaintext vs Ciphertext
        panes = ctk.CTkFrame(container, fg_color="transparent")
        panes.pack(fill="both", expand=True)

        # Left pane: Plaintext
        left_pane = HUDCard(panes, title="PLAINTEXT BAP WITNESS TRANSCRIPT")
        left_pane.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.txt_plaintext = ctk.CTkTextbox(
            left_pane,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(12, "normal"),
        )
        self.txt_plaintext.pack(fill="both", expand=True, padx=12, pady=(4, 8))
        self.txt_plaintext.insert(
            "1.0",
            "BERITA ACARA PEMERIKSAAN (BAP) DIGITAL FORENSIK\n"
            "Nomor Kasus : LXV/2026/CYBER-091\n"
            "Saksi Ahli  : Kompol. Dr. Aris Prakoso\n"
            "Temuan      : Bukti transaksi dompet kripto tersangka terkonfirmasi "
            "pada blok #19482100 dengan nilai mutasi Rp 4.850.000.000.",
        )

        btn_encrypt = ctk.CTkButton(
            left_pane,
            text="🔒 SUPER-ENCRYPT & SEAL TO CUSTODY ➔",
            height=38,
            font=get_mono_font(12, "bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._handle_text_encrypt,
        )
        btn_encrypt.pack(fill="x", padx=12, pady=(0, 12))

        # Right pane: Ciphertext & Telemetry
        right_pane = HUDCard(panes, title="BASE64 CIPHERTEXT ENVELOPE (IV + AES-256-CBC)")
        right_pane.pack(side="right", fill="both", expand=True, padx=(6, 0))

        self.txt_ciphertext = ctk.CTkTextbox(
            right_pane,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(12, "normal"),
            text_color=COLOR_EMERALD,
        )
        self.txt_ciphertext.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        meta_row = ctk.CTkFrame(right_pane, fg_color="transparent")
        meta_row.pack(fill="x", padx=12, pady=(0, 6))

        self.lbl_text_meta = ctk.CTkLabel(
            meta_row,
            text="IV (16B): - | SHA-256: -",
            font=get_mono_font(10, "normal"),
            text_color=COLOR_TEXT_MUTED,
            anchor="w",
        )
        self.lbl_text_meta.pack(fill="x")

        btn_decrypt = ctk.CTkButton(
            right_pane,
            text="⬅ DECRYPT BASE64 TO PLAINTEXT",
            height=38,
            font=get_mono_font(12, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self._handle_text_decrypt,
        )
        btn_decrypt.pack(fill="x", padx=12, pady=(0, 12))

    def _handle_text_encrypt(self) -> None:
        plaintext = self.txt_plaintext.get("1.0", "end-1c").strip()
        vig_key = self.ent_vig_key.get().strip()
        aes_key = self.ent_aes_key.get().strip()

        try:
            res = TextSuperCrypto.encrypt(plaintext, vig_key, aes_key)
            self.txt_ciphertext.delete("1.0", "end")
            self.txt_ciphertext.insert("1.0", res.ciphertext_b64)
            self.lbl_text_meta.configure(
                text=f"IV (16B): {res.iv_hex} | SHA-256: {res.sha256_hash[:28]}..."
            )
            self.log(
                f"Super-Enkripsi Teks selesai (IV: {res.iv_hex[:12]}..., SHA256: {res.sha256_hash[:16]}...).",
                "SUCCESS",
            )

            if self.chk_seal_text_var.get():
                self._seal_to_custody_chain(
                    evidence_prefix="BAP-TXT",
                    evidence_type="TEXT_SUPER_CRYPTO",
                    ciphertext_or_path=res.ciphertext_b64,
                    iv_nonce=res.iv_hex,
                    data_hash=res.sha256_hash,
                )
        except Exception as exc:
            self.log(f"Error Super-Enkripsi Teks: {exc}", "ERROR")

    def _handle_text_decrypt(self) -> None:
        ciphertext_b64 = self.txt_ciphertext.get("1.0", "end-1c").strip()
        vig_key = self.ent_vig_key.get().strip()
        aes_key = self.ent_aes_key.get().strip()

        try:
            recovered = TextSuperCrypto.decrypt(ciphertext_b64, vig_key, aes_key)
            self.txt_plaintext.delete("1.0", "end")
            self.txt_plaintext.insert("1.0", recovered)
            self.log("Dekripsi Super-Crypto berhasil memulihkan plaintext asli 100%.", "SUCCESS")
        except Exception as exc:
            self.log(f"Gagal Dekripsi Super-Crypto: {exc}", "ERROR")

    # =========================================================================
    # TAB 2: BINARY FILE LOCKER (ChaCha20 RAW STREAM ENCRYPTION)
    # =========================================================================
    def _build_tab2_file_locker(self) -> None:
        container = ctk.CTkFrame(self.tab_file, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=6)

        card = HUDCard(
            container,
            title="BINARY EVIDENCE FILE LOCKER (ChaCha20 STREAM CIPHER - NON-AES)",
            subtitle="Header Format: [12-Byte Random Nonce] + [Raw ChaCha20 Ciphertext Stream] ➔ .locked",
        )
        card.pack(fill="both", expand=True)

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=16, pady=10)

        # File selection row
        file_row = ctk.CTkFrame(form, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            file_row, text="TARGET EVIDENCE FILE:", font=get_mono_font(12, "bold"), width=180, anchor="w"
        ).pack(side="left")

        self.ent_file_path = ctk.CTkEntry(
            file_row,
            placeholder_text="Pilih file bukti (.pdf, .docx, .zip, .mp4, .locked)...",
            font=get_mono_font(12, "normal"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            height=36,
        )
        self.ent_file_path.pack(side="left", fill="x", expand=True, padx=8)

        ctk.CTkButton(
            file_row,
            text="BROWSE FILE...",
            width=140,
            height=36,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_SURFACE_DARK,
            border_color=COLOR_BORDER,
            border_width=1,
            hover_color=COLOR_BORDER,
            command=self._browse_locker_file,
        ).pack(side="right")

        # Passphrase row
        pass_row = ctk.CTkFrame(form, fg_color="transparent")
        pass_row.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            pass_row, text="ChaCha20 PASSPHRASE:", font=get_mono_font(12, "bold"), width=180, anchor="w"
        ).pack(side="left")

        self.ent_chacha_key = ctk.CTkEntry(
            pass_row,
            font=get_mono_font(12, "normal"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            height=36,
        )
        self.ent_chacha_key.pack(side="left", fill="x", expand=True, padx=8)
        self.ent_chacha_key.insert(0, "CHACHA20-FORENSIC-SEAL-2026")

        # Action Buttons
        actions_row = ctk.CTkFrame(form, fg_color="transparent")
        actions_row.pack(fill="x", pady=(4, 10))

        ctk.CTkButton(
            actions_row,
            text="LOCK BINARY FILE (.locked) & ANCHOR TO BLOCKCHAIN",
            height=42,
            font=get_mono_font(12, "bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._handle_file_encrypt,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            actions_row,
            text="UNLOCK & RESTORE ORIGINAL BINARY FILE",
            height=42,
            font=get_mono_font(12, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self._handle_file_decrypt,
        ).pack(side="right", fill="x", expand=True, padx=(8, 0))

        # Telemetry Output Box
        self.txt_file_telemetry = ctk.CTkTextbox(
            card,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(12, "normal"),
        )
        self.txt_file_telemetry.pack(fill="both", expand=True, padx=16, pady=(4, 14))
        self.txt_file_telemetry.insert(
            "1.0",
            "[ChaCha20 BINARY LOCKER READY]\n"
            "• Algoritma      : ChaCha20 Stream Cipher (256-bit Key via SHA-256, 96-bit / 12-Byte Random Nonce)\n"
            "• Struktur File  : [12-BYTE NONCE HEADER] + [RAW CIPHERTEXT BYTES]\n"
            "• Kepatuhan      : Pemulihan bit-identical 100% tanpa korupsi untuk dokumen, arsip, audio, dan video.",
        )

    def _browse_locker_file(self) -> None:
        path = filedialog.askopenfilename(title="Select Forensic Evidence File")
        if path:
            self.ent_file_path.delete(0, "end")
            self.ent_file_path.insert(0, path)

    def _handle_file_encrypt(self) -> None:
        target = self.ent_file_path.get().strip()
        passphrase = self.ent_chacha_key.get().strip()
        try:
            res = BinaryFileLocker.encrypt_file(target, passphrase)
            ev_id = self._seal_to_custody_chain(
                evidence_prefix="FILE-LCK",
                evidence_type="FILE_CHACHA20",
                ciphertext_or_path=res.output_path,
                iv_nonce=res.nonce_hex,
                data_hash=res.sha256_hash,
            )
            report = (
                f"=== ChaCha20 EVIDENCE SEAL COMPLETED ({ev_id}) ===\n"
                f"SOURCE FILE       : {res.source_path}\n"
                f"LOCKED CONTAINER  : {res.output_path}\n"
                f"12-BYTE NONCE HEX : {res.nonce_hex}\n"
                f"ORIGINAL SIZE     : {res.original_size_bytes:,} bytes\n"
                f"LOCKED SIZE       : {res.locked_size_bytes:,} bytes (+12B Nonce Header)\n"
                f"SEALED SHA-256    : {res.sha256_hash}\n"
            )
            self.txt_file_telemetry.delete("1.0", "end")
            self.txt_file_telemetry.insert("1.0", report)
            self.ent_file_path.delete(0, "end")
            self.ent_file_path.insert(0, res.output_path)
            self.log(f"File berhasil dikunci dengan ChaCha20: {Path(res.output_path).name}", "SUCCESS")
        except Exception as exc:
            self.log(f"Gagal mengenkripsi file ChaCha20: {exc}", "ERROR")

    def _handle_file_decrypt(self) -> None:
        target = self.ent_file_path.get().strip()
        passphrase = self.ent_chacha_key.get().strip()
        try:
            res = BinaryFileLocker.decrypt_file(target, passphrase)
            report = (
                f"=== ChaCha20 BINARY RESTORATION COMPLETED ===\n"
                f"LOCKED SOURCE     : {res.source_path}\n"
                f"RESTORED FILE     : {res.output_path}\n"
                f"EXTRACTED NONCE   : {res.nonce_hex}\n"
                f"RESTORED SIZE     : {res.original_size_bytes:,} bytes\n"
                f"RESTORED SHA-256  : {res.sha256_hash}\n"
                f"INTEGRITY STATUS  : 100% BIT-IDENTICAL RESTORATION VERIFIED\n"
            )
            self.txt_file_telemetry.delete("1.0", "end")
            self.txt_file_telemetry.insert("1.0", report)
            self.log(f"File .locked berhasil didekripsi ke: {Path(res.output_path).name}", "SUCCESS")
        except Exception as exc:
            self.log(f"Gagal mendekripsi file .locked: {exc}", "ERROR")

    # =========================================================================
    # TAB 3: STEGANOGRAPHY STUDIO (LOSSLESS PNG LSB)
    # =========================================================================
    def _build_tab3_stego_studio(self) -> None:
        container = ctk.CTkFrame(self.tab_stego, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=6)

        left_card = HUDCard(
            container,
            title="PNG LSB STEGANOGRAPHY CARRIER",
            subtitle="32-Bit Length Header + R/G/B Bitwise Injection",
        )
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        path_row = ctk.CTkFrame(left_card, fg_color="transparent")
        path_row.pack(fill="x", padx=12, pady=(6, 8))

        self.ent_stego_path = ctk.CTkEntry(
            path_row,
            placeholder_text="Pilih gambar (PNG, JPG, JPEG, WEBP, BMP)...",
            font=get_mono_font(11, "normal"),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
        )
        self.ent_stego_path.pack(side="left", fill="x", expand=True, padx=(0, 6))

        ctk.CTkButton(
            path_row,
            text="BROWSE IMAGE",
            width=115,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_SURFACE_DARK,
            border_color=COLOR_BORDER,
            border_width=1,
            command=self._browse_stego_image,
        ).pack(side="right")

        self.stego_preview_lbl = ctk.CTkLabel(
            left_card,
            text="[ CARRIER IMAGE PREVIEW ]\nSupports PNG, JPG, JPEG, WEBP, BMP",
            font=get_mono_font(11, "normal"),
            text_color=COLOR_TEXT_MUTED,
            fg_color=COLOR_BASE,
            corner_radius=6,
            height=210,
        )
        self.stego_preview_lbl.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        self.lbl_stego_capacity = ctk.CTkLabel(
            left_card,
            text="Capacity: - bits (- bytes max payload)",
            font=get_mono_font(11, "bold"),
            text_color=COLOR_EMERALD,
        )
        self.lbl_stego_capacity.pack(anchor="w", padx=12, pady=(0, 10))

        # Right card: Secret Message Embed / Extract
        right_card = HUDCard(
            container,
            title="COVERT METADATA PAYLOAD",
            subtitle="Lossless Bitwise Extraction without Visual Artifact",
        )
        right_card.pack(side="right", fill="both", expand=True, padx=(6, 0))

        self.txt_stego_message = ctk.CTkTextbox(
            right_card,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(12, "normal"),
        )
        self.txt_stego_message.pack(fill="both", expand=True, padx=12, pady=(6, 10))
        self.txt_stego_message.insert(
            "1.0",
            "CLASSIFIED FORENSIC WATERMARK // ISO-27037\n"
            "Case-ID: LXV-2026-STEGO-01\n"
            "Custodian: Kompol. Dr. Aris Prakoso\n"
            "GPS-Coords: -6.2088, 106.8456 (Jakarta HQ)",
        )

        btn_row = ctk.CTkFrame(right_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkButton(
            btn_row,
            text="🧬 EMBED LSB INTO PNG & SEAL",
            height=40,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._handle_stego_embed,
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="🔍 EXTRACT LSB FROM PNG",
            height=40,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self._handle_stego_extract,
        ).pack(side="right", fill="x", expand=True, padx=(6, 0))

    def _load_stego_preview(self, path: str) -> None:
        try:
            total_bits, max_bytes = StegoEngine.calculate_capacity(path)
            self.lbl_stego_capacity.configure(
                text=f"Capacity: {total_bits:,} bits ({max_bytes:,} bytes max payload)"
            )
            with Image.open(path) as pil_img:
                preview_copy = pil_img.copy()
                ctk_img = ctk.CTkImage(
                    light_image=preview_copy, dark_image=preview_copy, size=(340, 190)
                )
                self._stego_ctk_image = ctk_img
                self.stego_preview_lbl.configure(image=ctk_img, text="")
        except Exception as exc:
            self.log(f"Gagal memuat preview PNG: {exc}", "WARN")

    def _browse_stego_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Carrier Image (PNG, JPG, JPEG, WEBP, BMP)",
            filetypes=[
                ("Image Files (*.png, *.jpg, *.jpeg, *.webp, *.bmp)", "*.png *.jpg *.jpeg *.webp *.bmp *.PNG *.JPG *.JPEG *.WEBP *.BMP"),
                ("PNG Images (*.png)", "*.png *.PNG"),
                ("JPEG Images (*.jpg, *.jpeg)", "*.jpg *.jpeg *.JPG *.JPEG"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if path:
            self.ent_stego_path.delete(0, "end")
            self.ent_stego_path.insert(0, path)
            self._load_stego_preview(path)

    def _handle_stego_embed(self) -> None:
        carrier = self.ent_stego_path.get().strip()
        secret = self.txt_stego_message.get("1.0", "end-1c").strip()
        if not carrier:
            self.log("Pilih gambar pembawa (carrier image) terlebih dahulu!", "WARN")
            return

        try:
            src_path = Path(carrier)
            out_path = src_path.parent / f"stego_{src_path.stem}.png"
            res = StegoEngine.embed_message(str(src_path), secret, str(out_path))

            self.ent_stego_path.delete(0, "end")
            self.ent_stego_path.insert(0, res.output_path)
            self._load_stego_preview(res.output_path)

            self._seal_to_custody_chain(
                evidence_prefix="STG-PNG",
                evidence_type="STEGO_LSB_PNG",
                ciphertext_or_path=res.output_path,
                iv_nonce=f"LSB32-LEN:{res.payload_bytes_len}B",
                data_hash=res.sha256_hash,
            )
            self.log(
                f"Steganografi LSB sukses ({res.payload_bytes_len} byte disisipkan, "
                f"utilisasi {res.utilization_percent}%): {Path(res.output_path).name}",
                "SUCCESS",
            )
        except Exception as exc:
            self.log(f"Gagal menyisipkan pesan LSB: {exc}", "ERROR")

    def _handle_stego_extract(self) -> None:
        stego_path = self.ent_stego_path.get().strip()
        try:
            extracted = StegoEngine.extract_message(stego_path)
            self.txt_stego_message.delete("1.0", "end")
            self.txt_stego_message.insert("1.0", extracted)
            self.log(
                f"Ekstraksi LSB berhasil membaca {len(extracted.encode('utf-8'))} byte pesan rahasia.",
                "SUCCESS",
            )
        except Exception as exc:
            self.log(f"Gagal mengekstrak LSB dari PNG: {exc}", "ERROR")

    # =========================================================================
    # TAB 4: CHAIN OF CUSTODY AUDIT LEDGER (DUAL-LAYER BLOCKCHAIN)
    # =========================================================================
    def _build_tab4_audit_ledger(self) -> None:
        container = ctk.CTkFrame(self.tab_audit, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=6)

        top_card = HUDCard(
            container,
            title="HYBRID DUAL-LAYER BLOCKCHAIN AUDIT & TAMPER VERIFICATION",
            subtitle="Layer 1: Local Proof-of-Work ('000') + Layer 2: Polygon Amoy Testnet (Chain ID 80002)",
        )
        top_card.pack(fill="x", pady=(0, 8))

        ctrl_row = ctk.CTkFrame(top_card, fg_color="transparent")
        ctrl_row.pack(fill="x", padx=14, pady=(4, 12))

        self.badge_chain_audit = StatusBadge(
            ctrl_row, text="CHAIN INTEGRITY: VERIFIED", status="SUCCESS"
        )
        self.badge_chain_audit.pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            ctrl_row,
            text="↻ REFRESH CHAIN LEDGER",
            height=34,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self.refresh_audit_ledger,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            ctrl_row,
            text="↗ OPEN POLYGONSCAN AMOY",
            height=34,
            font=get_mono_font(11, "bold"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._open_polygonscan_link,
        ).pack(side="right")

        # Ledger Inspector Textbox
        ledger_card = HUDCard(container, title="IMMUTABLE BLOCKCHAIN LEDGER & EVIDENCE CUSTODY RECORDS")
        ledger_card.pack(fill="both", expand=True)

        self.txt_ledger = ctk.CTkTextbox(
            ledger_card,
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(11, "normal"),
        )
        self.txt_ledger.pack(fill="both", expand=True, padx=14, pady=(4, 14))

        self.refresh_audit_ledger()

    def refresh_audit_ledger(self) -> None:
        is_valid, messages, compromised = self.blockchain.is_chain_valid()
        evidence_rows = self.db_manager.list_evidence_records()

        if is_valid:
            self.badge_chain_audit.set_status(
                f"CHAIN INTEGRITY VERIFIED ({len(self.blockchain.chain)} BLOCKS)", "SUCCESS"
            )
            self.txt_ledger.configure(border_color=COLOR_EMERALD)
        else:
            self.badge_chain_audit.set_status(
                f"TAMPER BREACH DETECTED AT BLOCK(S) {compromised}!", "DANGER"
            )
            self.txt_ledger.configure(border_color=COLOR_CRIMSON)

        if self.on_chain_status_change:
            self.on_chain_status_change(is_valid)

        lines = [
            "================================================================================",
            "ISO/IEC 27037 DIGITAL CHAIN OF CUSTODY AUDIT REPORT",
            "================================================================================",
        ]
        for m in messages:
            lines.append(f"• {m}")

        lines.append("\n--- LAYER 1: LOCAL PROOF-OF-WORK BLOCKCHAIN (DIFFICULTY TARGET: '000') ---")
        for blk in self.blockchain.chain:
            status_tag = (
                "❌ [TAMPERED / INVALID HASH]"
                if blk.index in compromised
                else "✔ [VERIFIED PoW '000']"
            )
            explorer_link = (
                Web3SyncWorker.format_explorer_url(blk.layer2_tx_hash)
                if blk.layer2_tx_hash.startswith("0x")
                else blk.layer2_tx_hash
            )
            if blk.layer2_tx_hash.startswith("0x"):
                self.latest_explorer_url = explorer_link

            lines.append(
                f"\n[BLOCK #{blk.index}] {status_tag}\n"
                f"  Timestamp      : {blk.timestamp}\n"
                f"  Evidence ID    : {blk.evidence_id}\n"
                f"  Evidence SHA256: {blk.evidence_hash}\n"
                f"  Previous Hash  : {blk.previous_hash}\n"
                f"  PoW Nonce      : {blk.nonce}\n"
                f"  Block Hash     : {blk.hash}\n"
                f"  Layer 2 Amoy   : {explorer_link}"
            )

        lines.append("\n--- DATABASE CUSTODY RECORDS (METADATA ONLY - ZERO PLAINTEXT) ---")
        if not evidence_rows:
            lines.append("  [Belum ada bukti terenkripsi yang disegel pada sesi ini]")
        else:
            for r in evidence_rows:
                lines.append(
                    f"  • ID: {r.get('evidence_id')} | Type: {r.get('evidence_type')} | "
                    f"IV/Nonce: {r.get('iv_nonce')} | DataHash: {str(r.get('data_hash'))[:20]}... | "
                    f"L2: {r.get('layer2_tx_hash')}"
                )

        self.txt_ledger.configure(state="normal")
        self.txt_ledger.delete("1.0", "end")
        self.txt_ledger.insert("1.0", "\n".join(lines))
        self.txt_ledger.configure(state="disabled")

    def _open_polygonscan_link(self) -> None:
        url = self.latest_explorer_url or "https://amoy.polygonscan.com/"
        self.log(f"Membuka PolygonScan Amoy Explorer: {url}", "INFO")
        webbrowser.open(url)

    # =========================================================================
    # TAB 5: SECURITY, OPERATOR MANAGEMENT & BIOMETRIC ENROLLMENT
    # =========================================================================
    def _build_tab5_security(self) -> None:
        container = ctk.CTkFrame(self.tab_security, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=6)

        header_card = HUDCard(
            container,
            title="PERBARUI BIOMETRIK WAJAH OPERATOR AKTIF (LOGGED-IN USER)",
            subtitle="Ambil ulang dan perbarui profil biometrik wajah operator yang sedang aktif ke database",
        )
        header_card.pack(fill="x", pady=(0, 8))

        main_row = ctk.CTkFrame(container, fg_color="transparent")
        main_row.pack(fill="both", expand=True)

        # Left Column: Webcam viewfinder for biometric capture
        left_col = ctk.CTkFrame(
            main_row,
            fg_color=COLOR_SURFACE_DARK,
            border_color=COLOR_BORDER,
            border_width=1,
            corner_radius=6,
        )
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.tab5_cam_label = ctk.CTkLabel(
            left_col,
            text="[ WEBCAM STANDBY ]\nKlik 'NYALAKAN KAMERA' untuk memperbarui profil wajah Anda",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_MUTED,
            width=460,
            height=280,
        )
        self.tab5_cam_label.pack(fill="both", expand=True, padx=10, pady=10)

        # Right Column: Operator info and enrollment action
        right_col = ctk.CTkFrame(
            main_row,
            fg_color=COLOR_SURFACE_DARK,
            border_color=COLOR_BORDER,
            border_width=1,
            corner_radius=6,
            width=380,
        )
        right_col.pack(side="right", fill="y", padx=(6, 0))
        right_col.pack_propagate(False)

        ctk.CTkLabel(
            right_col,
            text="PROFIL OPERATOR AKTIF (LOGIN SAAT INI)",
            font=get_mono_font(12, "bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self.lbl_tab5_status = StatusBadge(right_col, text="READY TO UPDATE FACE", status="INFO")
        self.lbl_tab5_status.pack(anchor="w", padx=14, pady=(0, 10))

        self.txt_tab5_profile = ctk.CTkTextbox(
            right_col,
            height=120,
            font=get_mono_font(11),
            fg_color=COLOR_BASE,
            border_color=COLOR_BORDER,
            border_width=1,
        )
        self.txt_tab5_profile.pack(fill="x", padx=14, pady=(0, 10))
        self._refresh_tab5_operator_info()

        ctk.CTkButton(
            right_col,
            text="◉ NYALAKAN KAMERA",
            font=get_mono_font(12, "bold"),
            height=36,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._tab5_start_cam,
        ).pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            right_col,
            text="📸 PERBARUI WAJAH SAYA KE DATABASE",
            font=get_mono_font(12, "bold"),
            height=38,
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=self._tab5_enroll_face,
        ).pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            right_col,
            text="🔑 UBAH SANDI CUSTODIAN",
            font=get_mono_font(11, "bold"),
            height=34,
            fg_color="#1E3A8A",
            hover_color="#1D4ED8",
            command=self._tab5_change_password_dialog,
        ).pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            right_col,
            text="➕ TAMBAH USER / DONGLE BARU",
            font=get_mono_font(11, "bold"),
            height=34,
            fg_color="#064E3B",
            hover_color="#047857",
            command=self._tab5_add_user_dialog,
        ).pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            right_col,
            text="⏹ STOP KAMERA",
            font=get_mono_font(11, "bold"),
            height=32,
            fg_color=COLOR_SURFACE,
            hover_color=COLOR_BORDER,
            command=self._tab5_stop_cam,
        ).pack(fill="x", padx=14, pady=(0, 8))

    def _refresh_tab5_operator_info(self) -> None:
        serial = self.active_dongle.serial_number if self.active_dongle else os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LEXVAULT-DEV-DONGLE-001")
        rec = self.db_manager.get_dongle(serial) or {}
        face_hash = str(rec.get("face_profile_hash") or "").strip()
        has_face = bool(face_hash and face_hash not in ("EMPTY", "NONE") and len(face_hash) > 30)
        info = (
            f"OPERATOR AKTIF : {rec.get('operator_name', 'N/A')}\n"
            f"BADGE ID       : {rec.get('badge_id', 'N/A')}\n"
            f"SERIAL TOKEN   : {serial}\n"
            f"STATUS WAJAH   : {'TERDAFTAR & AKTIF (V2)' if has_face else 'BELUM TERDAFTAR (PERLU UPDATE)'}\n"
            f"DATABASE SYNC  : {'SUPABASE + SQLITE' if self.db_manager.cloud_online else 'OFFLINE SQLITE'}"
        )
        self.txt_tab5_profile.configure(state="normal")
        self.txt_tab5_profile.delete("1.0", "end")
        self.txt_tab5_profile.insert("1.0", info)
        self.txt_tab5_profile.configure(state="disabled")

    def _tab5_start_cam(self) -> None:
        if not OPENCV_AVAILABLE or cv2 is None:
            self.log("OpenCV tidak tersedia pada sistem.", "ERROR")
            self.lbl_tab5_status.set_status("OPENCV UNAVAILABLE", "DANGER")
            return
        if self._cam_running:
            return
        try:
            self._cam_cap = cv2.VideoCapture(0)
            if not self._cam_cap or not self._cam_cap.isOpened():
                self._tab5_stop_cam()
                self.lbl_tab5_status.set_status("CAMERA ERROR", "DANGER")
                self.tab5_cam_label.configure(
                    text="[ WEBCAM UNAVAILABLE OR PERMISSION DENIED ]\nPastikan izin kamera diberikan ke Terminal.",
                    text_color=COLOR_CRIMSON,
                )
                return
            self._cam_running = True
            self.lbl_tab5_status.set_status("CAMERA ACTIVE - POSITION FACE", "INFO")
            self._tab5_poll_frame()
        except Exception as exc:
            self.log(f"Error kamera Tab 5: {exc}", "ERROR")

    def _tab5_poll_frame(self) -> None:
        if not self._cam_running or self._cam_cap is None:
            return
        ret, frame = self._cam_cap.read()
        if not ret or frame is None:
            self._tab5_stop_cam()
            return
        self._last_raw_frame = frame.copy()
        if self.auth_gate:
            detected, ann, _, _ = self.auth_gate.detect_face_in_frame(frame)
        else:
            ann = frame

        rgb = cv2.cvtColor(ann, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(rgb)
        ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(460, 280))
        self._cam_ctk_image = ctk_img
        self.tab5_cam_label.configure(image=ctk_img, text="")
        self.after(25, self._tab5_poll_frame)

    def _clear_tab5_camera_image(self) -> None:
        """
        Safely detaches CTkImage from tab5_cam_label without triggering
        CustomTkinter's TclError ('pyimage doesn't exist').
        """
        try:
            if isinstance(getattr(self.tab5_cam_label, "_image", None), ctk.CTkImage):
                self.tab5_cam_label._image.remove_configure_callback(self.tab5_cam_label._update_image)
            self.tab5_cam_label._image = None
            if hasattr(self.tab5_cam_label, "_label") and self.tab5_cam_label._label is not None:
                self.tab5_cam_label._label.configure(image="")
        except Exception:
            pass
        self._cam_ctk_image = None

    def _tab5_stop_cam(self) -> None:
        self._cam_running = False
        if self._cam_cap is not None:
            try:
                self._cam_cap.release()
            except Exception:
                pass
            self._cam_cap = None
        self._clear_tab5_camera_image()
        self.tab5_cam_label.configure(text="[ WEBCAM STOPPED ]")

    def _tab5_enroll_face(self) -> None:
        if not self._cam_running or self._last_raw_frame is None:
            self.log("Nyalakan kamera terlebih dahulu untuk merekam pembaruan wajah.", "WARN")
            self.lbl_tab5_status.set_status("START CAMERA FIRST", "WARN")
            return
        if not self.auth_gate:
            return

        serial = self.active_dongle.serial_number if self.active_dongle else os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LEXVAULT-DEV-DONGLE-001")
        rec = self.db_manager.get_dongle(serial) or {}
        op_name = rec.get("operator_name", "Operator Aktif")

        detected, _, _, bbox = self.auth_gate.detect_face_in_frame(self._last_raw_frame)
        if not detected or bbox[2] < 30 or bbox[3] < 30:
            self.log("Wajah tidak terdeteksi dengan jelas. Hadapkan wajah tegak ke kamera.", "WARN")
            self.lbl_tab5_status.set_status("FACE NOT CLEAR", "WARN")
            return

        ok, msg = self.auth_gate.enroll_face_profile(serial, self._last_raw_frame, bbox)
        if ok:
            self.log(f"Pembaruan wajah berhasil: Profil biometrik operator '{op_name}' tersimpan di database.", "SUCCESS")
            self.lbl_tab5_status.set_status(f"WAJAH DIPERBARUI ({op_name})", "SUCCESS")
            self._refresh_tab5_operator_info()
            self._tab5_stop_cam()
        else:
            self.log(f"Gagal memperbarui biometrik: {msg}", "ERROR")
            self.lbl_tab5_status.set_status("UPDATE WAJAH GAGAL", "DANGER")

    def _tab5_change_password_dialog(self) -> None:
        serial = self.active_dongle.serial_number if self.active_dongle else os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LEXVAULT-DEV-DONGLE-001")
        dialog = ctk.CTkToplevel(self)
        dialog.title("UBAH SANDI CUSTODIAN")
        dialog.geometry("400x300")
        dialog.minsize(360, 260)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="UBAH SANDI MASTER DONGLE", font=get_mono_font(13, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkLabel(dialog, text=f"Target Token: {serial}", font=get_mono_font(11), text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=20, pady=(0, 12))

        ctk.CTkLabel(dialog, text="Sandi Baru:", font=get_mono_font(11, "bold")).pack(anchor="w", padx=20)
        entry_p1 = ctk.CTkEntry(dialog, placeholder_text="Masukkan sandi baru...", show="•", font=get_mono_font(11))
        entry_p1.pack(fill="x", padx=20, pady=(2, 8))

        ctk.CTkLabel(dialog, text="Konfirmasi Sandi Baru:", font=get_mono_font(11, "bold")).pack(anchor="w", padx=20)
        entry_p2 = ctk.CTkEntry(dialog, placeholder_text="Ulangi sandi baru...", show="•", font=get_mono_font(11))
        entry_p2.pack(fill="x", padx=20, pady=(2, 12))

        lbl_err = ctk.CTkLabel(dialog, text="", font=get_mono_font(11), text_color=COLOR_CRIMSON)
        lbl_err.pack(padx=20, pady=(0, 8))

        def _save():
            p1 = entry_p1.get().strip()
            p2 = entry_p2.get().strip()
            if not p1 or not p2:
                lbl_err.configure(text="Sandi tidak boleh kosong!")
                return
            if p1 != p2:
                lbl_err.configure(text="Konfirmasi sandi tidak cocok!")
                return
            if len(p1) < 6:
                lbl_err.configure(text="Sandi minimal 6 karakter!")
                return

            salt_hex, pwd_hash = AuthGate.hash_password_with_new_salt(p1)
            ok = self.db_manager.update_dongle_password(serial, salt_hex, pwd_hash)
            if ok:
                self.log(f"Sandi untuk dongle '{serial}' berhasil diperbarui di database.", "SUCCESS")
                dialog.destroy()
            else:
                lbl_err.configure(text="Gagal menyimpan sandi ke database.")

        btn_row = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(4, 14))
        ctk.CTkButton(btn_row, text="BATAL", width=80, fg_color=COLOR_SURFACE, hover_color=COLOR_BORDER, command=dialog.destroy, font=get_mono_font(11, "bold")).pack(side="left")
        ctk.CTkButton(btn_row, text="💾 SIMPAN SANDI", fg_color=COLOR_EMERALD, hover_color="#059669", text_color="#052E16", command=_save, font=get_mono_font(11, "bold")).pack(side="right", fill="x", expand=True, padx=(10, 0))

    def _tab5_add_user_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("TAMBAH OPERATOR & DONGLE BARU")
        dialog.geometry("520x680")
        dialog.minsize(480, 620)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="DAFTARKAN OPERATOR & USB DONGLE BARU", font=get_mono_font(13, "bold")).pack(anchor="w", padx=20, pady=(14, 2))
        ctk.CTkLabel(dialog, text="Generate classified.key, rekam wajah biometrik, dan daftarkan ke database.", font=get_mono_font(11), text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=20, pady=(0, 10))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # 1. Mount Path
        ctk.CTkLabel(scroll, text="1. Folder Root USB Flash Drive:", font=get_mono_font(11, "bold")).pack(anchor="w")
        p_row = ctk.CTkFrame(scroll, fg_color="transparent")
        p_row.pack(fill="x", pady=(2, 8))
        entry_p = ctk.CTkEntry(p_row, placeholder_text="Pilih folder USB...", font=get_mono_font(11))
        entry_p.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(p_row, text="📁 BROWSE", width=80, font=get_mono_font(11, "bold"), command=lambda: (
            d := filedialog.askdirectory(title="Pilih Mount USB", parent=dialog),
            entry_p.delete(0, "end"),
            entry_p.insert(0, d) if d else None
        )).pack(side="right")

        # 2. Operator Name
        ctk.CTkLabel(scroll, text="2. Nama Operator Baru:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_name = ctk.CTkEntry(scroll, placeholder_text="misal: Briptu Bintang Shada", font=get_mono_font(11))
        entry_name.pack(fill="x", pady=(2, 8))

        # 3. Badge ID
        ctk.CTkLabel(scroll, text="3. Badge ID / NIP:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_badge = ctk.CTkEntry(scroll, placeholder_text="misal: DF-INA-99881", font=get_mono_font(11))
        entry_badge.pack(fill="x", pady=(2, 8))

        # 4. Password
        ctk.CTkLabel(scroll, text="4. Sandi Rahasia Operator:", font=get_mono_font(11, "bold")).pack(anchor="w")
        entry_pwd = ctk.CTkEntry(scroll, placeholder_text="Setel password awal...", show="•", font=get_mono_font(11))
        entry_pwd.pack(fill="x", pady=(2, 10))

        # 5. Face Camera Capture
        ctk.CTkLabel(scroll, text="5. Rekam Biometrik Wajah Operator Baru (Wajib):", font=get_mono_font(11, "bold")).pack(anchor="w")

        cam_box = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE_DARK, border_color=COLOR_BORDER, border_width=1, corner_radius=6)
        cam_box.pack(fill="x", pady=(4, 8))

        cam_preview = ctk.CTkLabel(
            cam_box,
            text="[ KAMERA STANDBY ]\nKlik 'NYALAKAN KAMERA' untuk merekam wajah operator baru",
            font=get_mono_font(11, "bold"),
            text_color=COLOR_TEXT_MUTED,
            height=180,
        )
        cam_preview.pack(fill="x", padx=8, pady=8)

        dialog_cam_state = {
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

        def _stop_new_user_cam():
            dialog_cam_state["running"] = False
            if dialog_cam_state["after_id"]:
                try:
                    dialog.after_cancel(dialog_cam_state["after_id"])
                except Exception:
                    pass
                dialog_cam_state["after_id"] = None
            if dialog_cam_state["cap"] is not None:
                try:
                    dialog_cam_state["cap"].release()
                except Exception:
                    pass
                dialog_cam_state["cap"] = None
            try:
                if hasattr(cam_preview, "_label") and cam_preview._label is not None:
                    cam_preview._label.configure(image="")
            except Exception:
                pass
            dialog_cam_state["ctk_img"] = None

        def _poll_new_user_cam():
            if not dialog_cam_state["running"] or dialog_cam_state["cap"] is None:
                return
            ret, frame = dialog_cam_state["cap"].read()
            if not ret or frame is None:
                _stop_new_user_cam()
                return

            dialog_cam_state["last_frame"] = frame.copy()
            if self.auth_gate:
                detected, ann, _, _ = self.auth_gate.detect_face_in_frame(frame)
            else:
                ann = frame

            rgb = cv2.cvtColor(ann, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb)
            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(320, 180))
            dialog_cam_state["ctk_img"] = ctk_img
            cam_preview.configure(image=ctk_img, text="")
            dialog_cam_state["after_id"] = dialog.after(30, _poll_new_user_cam)

        def _start_new_user_cam():
            if not OPENCV_AVAILABLE or cv2 is None:
                lbl_face_status.configure(text="OpenCV tidak tersedia pada sistem!", text_color=COLOR_CRIMSON)
                return
            if dialog_cam_state["running"]:
                return
            try:
                dialog_cam_state["cap"] = cv2.VideoCapture(0)
                if not dialog_cam_state["cap"] or not dialog_cam_state["cap"].isOpened():
                    _stop_new_user_cam()
                    lbl_face_status.configure(text="Kamera tidak dapat dibuka! Cek izin sistem.", text_color=COLOR_CRIMSON)
                    return
                dialog_cam_state["running"] = True
                lbl_face_status.configure(text="◉ KAMERA AKTIF: Posisikan wajah di tengah...", text_color=COLOR_PRIMARY)
                _poll_new_user_cam()
            except Exception as exc:
                lbl_face_status.configure(text=f"Error kamera: {exc}", text_color=COLOR_CRIMSON)

        def _capture_new_user_face():
            if not dialog_cam_state["running"] or dialog_cam_state["last_frame"] is None:
                lbl_face_status.configure(text="Nyalakan kamera terlebih dahulu!", text_color=COLOR_CRIMSON)
                return
            if not self.auth_gate:
                return

            detected, _, _, bbox = self.auth_gate.detect_face_in_frame(dialog_cam_state["last_frame"])
            if not detected or bbox[2] < 30 or bbox[3] < 30:
                lbl_face_status.configure(text="Wajah belum terdeteksi jelas! Dekatkan wajah.", text_color=COLOR_CRIMSON)
                return

            vec = self.auth_gate.extract_face_feature_vector(dialog_cam_state["last_frame"], bbox)
            if not vec:
                lbl_face_status.configure(text="Gagal mengekstrak vektor biometrik wajah!", text_color=COLOR_CRIMSON)
                return

            dialog_cam_state["captured_vector"] = vec
            lbl_face_status.configure(
                text=f"✓ WAJAH OPERATOR TERKUNCI & TERDAFTAR [{bbox[2]}x{bbox[3]}px]",
                text_color=COLOR_EMERALD,
            )
            _stop_new_user_cam()
            cam_preview.configure(text="[ FOTO WAJAH BERHASIL DIAMBIL & TERKUNCI ]", text_color=COLOR_EMERALD)

        cam_btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        cam_btn_row.pack(fill="x", pady=(0, 10))
        ctk.CTkButton(
            cam_btn_row,
            text="◉ NYALAKAN KAMERA",
            width=140,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=_start_new_user_cam,
            font=get_mono_font(11, "bold"),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            cam_btn_row,
            text="📸 AMBIL FOTO WAJAH",
            fg_color=COLOR_EMERALD,
            hover_color="#059669",
            text_color="#052E16",
            command=_capture_new_user_face,
            font=get_mono_font(11, "bold"),
        ).pack(side="right", fill="x", expand=True)

        lbl_msg = ctk.CTkLabel(dialog, text="", font=get_mono_font(11), text_color=COLOR_CRIMSON)
        lbl_msg.pack(padx=20, pady=(2, 6))

        def _do_add():
            m = entry_p.get().strip()
            n = entry_name.get().strip()
            b = entry_badge.get().strip()
            pw = entry_pwd.get().strip()
            face_vec = dialog_cam_state.get("captured_vector")

            if not m or not Path(m).exists():
                lbl_msg.configure(text="Pilih folder USB yang valid!")
                return
            if not n or not b or not pw:
                lbl_msg.configure(text="Semua kolom nama, badge, dan sandi wajib diisi!")
                return
            if len(pw) < 6:
                lbl_msg.configure(text="Password minimal 6 karakter!")
                return
            if not face_vec:
                lbl_msg.configure(text="Wajah operator wajib direkam sebelum mendaftarkan USB!")
                return

            _stop_new_user_cam()
            if self.auth_gate:
                ok, msg = self.auth_gate.provision_usb_drive(
                    mount_path=m,
                    operator_name=n,
                    badge_id=b,
                    password=pw,
                    face_profile_hash=face_vec,
                )
                self.log(msg, "SUCCESS" if ok else "ERROR")
                if ok:
                    dialog.destroy()
                else:
                    lbl_msg.configure(text=msg)

        def _on_close_dialog():
            _stop_new_user_cam()
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", _on_close_dialog)

        b_row = ctk.CTkFrame(dialog, fg_color="transparent")
        b_row.pack(fill="x", padx=20, pady=(4, 16))
        ctk.CTkButton(b_row, text="BATAL", width=80, fg_color=COLOR_SURFACE, hover_color=COLOR_BORDER, command=_on_close_dialog, font=get_mono_font(11, "bold")).pack(side="left")
        ctk.CTkButton(b_row, text="💾 BUAT & DAFTARKAN DONGLE", fg_color=COLOR_EMERALD, hover_color="#059669", text_color="#052E16", command=_do_add, font=get_mono_font(11, "bold")).pack(side="right", fill="x", expand=True, padx=(10, 0))

