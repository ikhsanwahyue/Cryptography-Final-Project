"""
Dual-Layer Database Manager for LexVault.
Provides primary cloud persistence via Supabase with automatic, seamless
failover and local mirroring to SQLite3 (offline_vault.db).
"""

import hashlib
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from supabase import Client, create_client
    SUPABASE_AVAILABLE = True
except ImportError:
    Client = Any  # type: ignore
    SUPABASE_AVAILABLE = False


class DatabaseManager:
    """
    Manages forensic custody persistence across Supabase Cloud and Local SQLite3.
    Automatically falls back to SQLite (`offline_vault.db`) when offline or when
    Supabase credentials are unconfigured or unreachable.
    """

    def __init__(
        self,
        sqlite_path: Optional[str] = None,
        logger_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.base_dir = Path(__file__).resolve().parent.parent
        default_db = os.getenv("SQLITE_DB_PATH", "offline_vault.db")
        self.sqlite_path = Path(sqlite_path) if sqlite_path else (self.base_dir / default_db)
        self.schema_path = Path(__file__).resolve().parent / "schema.sql"
        self.logger_callback = logger_callback
        self._lock = threading.RLock()

        self.supabase_url = os.getenv("SUPABASE_URL", "").strip()
        self.supabase_key = os.getenv("SUPABASE_KEY", "").strip()
        self.supabase_client: Optional[Client] = None
        self.cloud_online: bool = False

        self._init_sqlite()
        self._init_supabase()
        self._seed_default_dongle()

    def _log(self, message: str, level: str = "INFO") -> None:
        if self.logger_callback:
            try:
                self.logger_callback(message, level)
            except Exception:
                pass

    def _get_sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.sqlite_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self) -> None:
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                if self.schema_path.exists():
                    schema_sql = self.schema_path.read_text(encoding="utf-8")
                    conn.executescript(schema_sql)
                else:
                    conn.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS authorized_dongles (
                            serial_number VARCHAR(128) PRIMARY KEY,
                            operator_name VARCHAR(128) NOT NULL,
                            badge_id VARCHAR(64) NOT NULL,
                            token_signature VARCHAR(128) NOT NULL,
                            password_salt VARCHAR(64) NOT NULL,
                            password_hash VARCHAR(128) NOT NULL,
                            face_profile_hash VARCHAR(128),
                            is_active BOOLEAN NOT NULL DEFAULT 1,
                            registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE IF NOT EXISTS evidence_records (
                            evidence_id VARCHAR(64) PRIMARY KEY,
                            evidence_type VARCHAR(32) NOT NULL,
                            ciphertext_or_asset_path TEXT NOT NULL,
                            iv_nonce VARCHAR(128) NOT NULL,
                            data_hash VARCHAR(64) NOT NULL,
                            layer1_block_hash VARCHAR(64) NOT NULL,
                            layer2_tx_hash VARCHAR(128),
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE IF NOT EXISTS audit_blocks (
                            block_index INTEGER PRIMARY KEY,
                            timestamp VARCHAR(64) NOT NULL,
                            evidence_id VARCHAR(64) NOT NULL,
                            evidence_hash VARCHAR(64) NOT NULL,
                            previous_hash VARCHAR(64) NOT NULL,
                            nonce INTEGER NOT NULL,
                            block_hash VARCHAR(64) NOT NULL,
                            layer2_tx_hash VARCHAR(128),
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                conn.commit()
                self._log(f"SQLite local vault initialized at {self.sqlite_path.name}", "INFO")
            finally:
                conn.close()

    def _init_supabase(self) -> None:
        if not SUPABASE_AVAILABLE:
            self.cloud_online = False
            self._log("supabase-py not installed; operating in SQLite Local Vault mode.", "WARN")
            return

        if (
            not self.supabase_url
            or not self.supabase_key
            or "your-project-id" in self.supabase_url
            or "your-supabase" in self.supabase_key
        ):
            self.cloud_online = False
            self._log("Supabase credentials not configured; active failover to offline_vault.db.", "WARN")
            return

        try:
            self.supabase_client = create_client(self.supabase_url, self.supabase_key)
            # Lightweight connectivity check
            self.supabase_client.table("authorized_dongles").select("serial_number").limit(1).execute()
            self.cloud_online = True
            self._log("Supabase cloud database connected and verified.", "SUCCESS")
        except Exception as exc:
            self.cloud_online = False
            self._log(f"Supabase unreachable ({exc}); switched to SQLite offline_vault.db.", "WARN")

    def _seed_default_dongle(self) -> None:
        """
        Ensures a default forensic custodian hardware token and password record
        exist so the system is immediately operational out of the box.
        Default Master Password: LexVault#2026
        """
        default_serial = os.getenv("LEXVAULT_DEFAULT_DONGLE_SERIAL", "LEXVAULT-DEV-DONGLE-001")
        existing = self.get_dongle(default_serial)
        if existing is not None:
            return

        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
        default_password = os.getenv("LEXVAULT_DEFAULT_PASSWORD", "LexVault#2026")
        pwd_hash = hashlib.sha256(salt_bytes + default_password.encode("utf-8")).hexdigest()
        token_sig = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"

        self.register_dongle(
            serial_number=default_serial,
            operator_name="Kompol. Dr. Aris Prakoso, M.Si (Forensik)",
            badge_id="DF-INA-88219",
            token_signature=token_sig,
            password_salt=salt_hex,
            password_hash=pwd_hash,
            face_profile_hash=hashlib.sha256(b"LEXVAULT_BIOMETRIC_ENROLLED_V1").hexdigest(),
            is_active=True,
        )

    # =========================================================================
    # DONGLE & AUTHENTICATION PERSISTENCE
    # =========================================================================
    def register_dongle(
        self,
        serial_number: str,
        operator_name: str,
        badge_id: str,
        token_signature: str,
        password_salt: str,
        password_hash: str,
        face_profile_hash: Optional[str] = None,
        is_active: bool = True,
    ) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "serial_number": serial_number,
            "operator_name": operator_name,
            "badge_id": badge_id,
            "token_signature": token_signature,
            "password_salt": password_salt,
            "password_hash": password_hash,
            "face_profile_hash": face_profile_hash or "",
            "is_active": bool(is_active),
            "registered_at": now_iso,
        }

        if self.cloud_online and self.supabase_client is not None:
            try:
                self.supabase_client.table("authorized_dongles").upsert(payload).execute()
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase write failed ({exc}), persisting to local SQLite.", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO authorized_dongles (
                        serial_number, operator_name, badge_id, token_signature,
                        password_salt, password_hash, face_profile_hash, is_active, registered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        serial_number,
                        operator_name,
                        badge_id,
                        token_signature,
                        password_salt,
                        password_hash,
                        face_profile_hash or "",
                        1 if is_active else 0,
                        now_iso,
                    ),
                )
                conn.commit()
                return True
            finally:
                conn.close()

    def get_dongle(self, serial_number: str) -> Optional[Dict[str, Any]]:
        if self.cloud_online and self.supabase_client is not None:
            try:
                resp = (
                    self.supabase_client.table("authorized_dongles")
                    .select("*")
                    .eq("serial_number", serial_number)
                    .limit(1)
                    .execute()
                )
                if resp.data:
                    row = dict(resp.data[0])
                    row["is_active"] = bool(row.get("is_active", False))
                    return row
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase read timeout/error ({exc}), reading from SQLite.", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute(
                    "SELECT * FROM authorized_dongles WHERE serial_number = ?",
                    (serial_number,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                result = dict(row)
                result["is_active"] = bool(result.get("is_active", 0))
                return result
            finally:
                conn.close()

    def list_dongles(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute("SELECT * FROM authorized_dongles ORDER BY registered_at DESC")
                rows = [dict(r) for r in cur.fetchall()]
                for r in rows:
                    r["is_active"] = bool(r.get("is_active", 0))
                return rows
            finally:
                conn.close()

    def update_dongle_password(self, serial_number: str, password_salt: str, password_hash: str) -> bool:
        if self.cloud_online and self.supabase_client is not None:
            try:
                self.supabase_client.table("authorized_dongles").update(
                    {"password_salt": password_salt, "password_hash": password_hash}
                ).eq("serial_number", serial_number).execute()
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase password update fallback ({exc}).", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                conn.execute(
                    """
                    UPDATE authorized_dongles
                    SET password_salt = ?, password_hash = ?
                    WHERE serial_number = ?
                    """,
                    (password_salt, password_hash, serial_number),
                )
                conn.commit()
                return True
            finally:
                conn.close()

    # =========================================================================
    # EVIDENCE RECORDS PERSISTENCE
    # =========================================================================
    def save_evidence_record(
        self,
        evidence_id: str,
        evidence_type: str,
        ciphertext_or_asset_path: str,
        iv_nonce: str,
        data_hash: str,
        layer1_block_hash: str,
        layer2_tx_hash: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Persists cryptographic evidence metadata to Supabase and local SQLite.
        Never stores plaintext or secret keys.
        Returns (saved_ok, storage_mode) where storage_mode is 'SUPABASE+SQLITE' or 'SQLITE_FALLBACK'.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "ciphertext_or_asset_path": ciphertext_or_asset_path,
            "iv_nonce": iv_nonce,
            "data_hash": data_hash,
            "layer1_block_hash": layer1_block_hash,
            "layer2_tx_hash": layer2_tx_hash or "PENDING_SYNC",
            "created_at": now_iso,
        }

        synced_cloud = False
        if self.cloud_online and self.supabase_client is not None:
            try:
                self.supabase_client.table("evidence_records").upsert(payload).execute()
                synced_cloud = True
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase evidence insert failed ({exc}); using SQLite fallback.", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_records (
                        evidence_id, evidence_type, ciphertext_or_asset_path,
                        iv_nonce, data_hash, layer1_block_hash, layer2_tx_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        evidence_type,
                        ciphertext_or_asset_path,
                        iv_nonce,
                        data_hash,
                        layer1_block_hash,
                        layer2_tx_hash or "PENDING_SYNC",
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        mode = "SUPABASE+SQLITE" if synced_cloud else "SQLITE_FALLBACK"
        return True, mode

    def update_evidence_layer2_tx(self, evidence_id: str, tx_hash: str) -> None:
        if self.cloud_online and self.supabase_client is not None:
            try:
                self.supabase_client.table("evidence_records").update(
                    {"layer2_tx_hash": tx_hash}
                ).eq("evidence_id", evidence_id).execute()
                self.supabase_client.table("audit_blocks").update(
                    {"layer2_tx_hash": tx_hash}
                ).eq("evidence_id", evidence_id).execute()
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase L2 tx update failed ({exc}); updated locally.", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                conn.execute(
                    "UPDATE evidence_records SET layer2_tx_hash = ? WHERE evidence_id = ?",
                    (tx_hash, evidence_id),
                )
                conn.execute(
                    "UPDATE audit_blocks SET layer2_tx_hash = ? WHERE evidence_id = ?",
                    (tx_hash, evidence_id),
                )
                conn.commit()
            finally:
                conn.close()

    def list_evidence_records(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute(
                    "SELECT * FROM evidence_records ORDER BY created_at DESC"
                )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    # =========================================================================
    # LAYER 1 BLOCKCHAIN LEDGER PERSISTENCE
    # =========================================================================
    def save_audit_block(self, block_data: Dict[str, Any]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "block_index": int(block_data["index"]),
            "timestamp": str(block_data["timestamp"]),
            "evidence_id": str(block_data["evidence_id"]),
            "evidence_hash": str(block_data["evidence_hash"]),
            "previous_hash": str(block_data["previous_hash"]),
            "nonce": int(block_data["nonce"]),
            "block_hash": str(block_data["hash"]),
            "layer2_tx_hash": str(block_data.get("layer2_tx_hash") or "PENDING_SYNC"),
            "created_at": now_iso,
        }

        if self.cloud_online and self.supabase_client is not None:
            try:
                self.supabase_client.table("audit_blocks").upsert(payload).execute()
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase block save fallback ({exc}).", "WARN")

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO audit_blocks (
                        block_index, timestamp, evidence_id, evidence_hash,
                        previous_hash, nonce, block_hash, layer2_tx_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["block_index"],
                        payload["timestamp"],
                        payload["evidence_id"],
                        payload["evidence_hash"],
                        payload["previous_hash"],
                        payload["nonce"],
                        payload["block_hash"],
                        payload["layer2_tx_hash"],
                        payload["created_at"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def load_audit_blocks(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute(
                    "SELECT * FROM audit_blocks ORDER BY block_index ASC"
                )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def tamper_block_for_audit_test(self, block_index: int, fake_evidence_hash: str) -> bool:
        """
        Utility method to directly alter a stored block's evidence_hash in SQLite
        without re-mining, allowing forensic demonstration of anti-tamper detection.
        """
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute(
                    "UPDATE audit_blocks SET evidence_hash = ? WHERE block_index = ?",
                    (fake_evidence_hash, block_index),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

