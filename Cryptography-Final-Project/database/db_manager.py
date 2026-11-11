"""
Dual-Layer Database Manager for LexVault.
Provides primary cloud persistence via Supabase with automatic, seamless
failover and local mirroring to SQLite3 (offline_vault.db).
"""

import hashlib
import json
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
        # Explicitly reload .env with full absolute path to avoid missing environment vars
        env_file = self.base_dir / ".env"
        if env_file.exists():
            load_dotenv(dotenv_path=env_file, override=True)

        self.sample_dir = self.base_dir / "dongle_sample"
        self.sample_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_sqlite_path = self.sample_dir / "offline_vault.db"

        # Migrate legacy root offline_vault.db into dongle_sample/offline_vault.db if present
        legacy_root_db = self.base_dir / "offline_vault.db"
        if legacy_root_db.exists():
            try:
                import shutil
                if not self.fallback_sqlite_path.exists():
                    shutil.copy2(legacy_root_db, self.fallback_sqlite_path)
                legacy_root_db.unlink()
            except Exception:
                pass

        # Migrate legacy database/default_face_seed.hex into dongle_sample/default_face_seed.hex
        legacy_seed = Path(__file__).resolve().parent / "default_face_seed.hex"
        self.seed_face_path = self.sample_dir / "default_face_seed.hex"
        if legacy_seed.exists():
            try:
                if not self.seed_face_path.exists():
                    self.seed_face_path.write_text(legacy_seed.read_text(encoding="utf-8"), encoding="utf-8")
                legacy_seed.unlink()
            except Exception:
                pass

        default_db = os.getenv("SQLITE_DB_PATH", "dongle_sample/offline_vault.db")
        if default_db == "offline_vault.db":
            default_db = "dongle_sample/offline_vault.db"
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

    def set_active_dongle_storage(self, mount_dir: Optional[Path] = None) -> Path:
        """
        Switches the active SQLite database (`offline_vault.db`) to live directly inside:
        - The mounted physical USB Flashdisk (`/Volumes/<USB_NAME>/offline_vault.db`), OR
        - `dongle_sample/offline_vault.db` when Bypass USB / Virtual Dev Dongle is active.
        Ensures only the physical owner of the USB drive (or `dongle_sample` in dev mode) holds the database.
        """
        with self._lock:
            target_dir = Path(mount_dir) if (mount_dir and Path(mount_dir).exists()) else self.sample_dir
            target_db = target_dir / "offline_vault.db"
            if self.sqlite_path != target_db or not target_db.exists():
                self.sqlite_path = target_db
                self._init_sqlite()
                self._sync_from_key_file(target_dir / "classified.key")
            return self.sqlite_path

    def _sync_from_key_file(self, key_file: Path) -> None:
        """If classified.key on the USB/dongle_sample carries embedded dongle & face records, ensure SQLite on the USB has them."""
        if not key_file.exists():
            return
        try:
            data = json.loads(key_file.read_text(encoding="utf-8"))
            serial = str(data.get("hardware_binding") or "").strip()
            if not serial:
                return
            face_h = str(data.get("face_profile_hash") or "")
            pwd_salt = str(data.get("password_salt") or "")
            pwd_hash = str(data.get("password_hash") or "")
            op_name = str(data.get("operator_name") or "Kompol. Dr. Aris Prakoso, M.Si (Forensik)")
            badge = str(data.get("badge_id") or "DF-INA-88219")
            sig = str(data.get("signature_sha256") or "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")

            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute("SELECT face_profile_hash FROM authorized_dongles WHERE serial_number = ?", (serial,))
                row = cur.fetchone()
                if not row and pwd_salt and pwd_hash:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    front_e, left_e, right_e, model_e = self._unpack_multipose_columns(face_h)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO authorized_dongles (
                            serial_number, operator_name, badge_id, token_signature,
                            password_salt, password_hash, face_profile_hash,
                            face_embedding_front, face_embedding_left, face_embedding_right,
                            biometric_model, biometric_updated_at, is_active, registered_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                        """,
                        (serial, op_name, badge, sig, pwd_salt, pwd_hash, face_h, front_e, left_e, right_e, model_e, now_iso, now_iso),
                    )
                    conn.commit()
                elif row and face_h.startswith("LXV_SFACE_V3:") and not str(row[0] or "").startswith("LXV_SFACE_V3:"):
                    now_iso = datetime.now(timezone.utc).isoformat()
                    front_e, left_e, right_e, model_e = self._unpack_multipose_columns(face_h)
                    conn.execute(
                        """
                        UPDATE authorized_dongles
                        SET face_profile_hash = ?, face_embedding_front = ?, face_embedding_left = ?,
                            face_embedding_right = ?, biometric_model = ?, biometric_updated_at = ?
                        WHERE serial_number = ?
                        """,
                        (face_h, front_e, left_e, right_e, model_e, now_iso, serial),
                    )
                    conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    def _sync_to_key_file(self, serial_number: str) -> None:
        """Mirrors the dongle's face_profile_hash and credentials into classified.key in the active dongle directory."""
        key_file = self.sqlite_path.parent / "classified.key"
        if not key_file.exists():
            return
        try:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute("SELECT * FROM authorized_dongles WHERE serial_number = ?", (serial_number,))
                row = cur.fetchone()
            finally:
                conn.close()
            if not row:
                return
            rec = dict(row)
            key_data = json.loads(key_file.read_text(encoding="utf-8"))
            key_data["operator_name"] = rec.get("operator_name", "")
            key_data["badge_id"] = rec.get("badge_id", "")
            key_data["password_salt"] = rec.get("password_salt", "")
            key_data["password_hash"] = rec.get("password_hash", "")
            key_data["face_profile_hash"] = rec.get("face_profile_hash", "")
            key_file.write_text(json.dumps(key_data, indent=2), encoding="utf-8")
        except Exception:
            pass

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
                            face_profile_hash TEXT,
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
                # Ensure new v2.0 3-Pose Neural Biometric columns exist in SQLite
                existing_cols = {
                    row[1] for row in conn.execute("PRAGMA table_info(authorized_dongles)").fetchall()
                }
                migrations = [
                    ("face_embedding_front", "TEXT"),
                    ("face_embedding_left", "TEXT"),
                    ("face_embedding_right", "TEXT"),
                    ("biometric_model", "VARCHAR(64) DEFAULT 'YuNet+SFace-128D-3Pose'"),
                    ("biometric_updated_at", "TIMESTAMP"),
                ]
                for col_name, col_type in migrations:
                    if col_name not in existing_cols:
                        try:
                            conn.execute(f"ALTER TABLE authorized_dongles ADD COLUMN {col_name} {col_type}")
                        except Exception:
                            pass
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

        default_face = ""
        if self.seed_face_path.exists():
            seed_content = self.seed_face_path.read_text(encoding="utf-8").strip()
            if seed_content.startswith("LXV_SFACE_V3:"):
                default_face = seed_content

        self.register_dongle(
            serial_number=default_serial,
            operator_name="Kompol. Dr. Aris Prakoso, M.Si (Forensik)",
            badge_id="DF-INA-88219",
            token_signature=token_sig,
            password_salt=salt_hex,
            password_hash=pwd_hash,
            face_profile_hash=default_face,
            is_active=True,
        )

    @staticmethod
    def _unpack_multipose_columns(face_profile_hash: Optional[str]) -> Tuple[str, str, str, str]:
        """
        Extracts individual (front, left, right, model) strings from an LXV_SFACE_V3 bundle.
        """
        if not face_profile_hash or not face_profile_hash.startswith("LXV_SFACE_V3:"):
            return "", "", "", "YuNet+SFace-128D-3Pose"
        try:
            data = json.loads(face_profile_hash[len("LXV_SFACE_V3:"):])
            poses = data.get("poses", data)
            front = str(poses.get("front") or "")
            left = str(poses.get("left") or "")
            right = str(poses.get("right") or "")
            model = str(data.get("model") or "YuNet+SFace-128D-3Pose")
            return front, left, right, model
        except Exception:
            return "", "", "", "YuNet+SFace-128D-3Pose"

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
        front_emb, left_emb, right_emb, bio_model = self._unpack_multipose_columns(face_profile_hash)
        base_payload = {
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
        extended_payload = {
            **base_payload,
            "face_embedding_front": front_emb,
            "face_embedding_left": left_emb,
            "face_embedding_right": right_emb,
            "biometric_model": bio_model,
            "biometric_updated_at": now_iso,
        }

        if self.supabase_client is None and self.supabase_url and self.supabase_key:
            self._init_supabase()

        if self.supabase_client is not None:
            try:
                self.supabase_client.table("authorized_dongles").upsert(extended_payload).execute()
                self.cloud_online = True
                self._log(f"Supabase Cloud: Dongle '{serial_number}' ({operator_name}) tersimpan lengkap ke Cloud.", "SUCCESS")
            except Exception:
                try:
                    self.supabase_client.table("authorized_dongles").upsert(base_payload).execute()
                    self.cloud_online = True
                    self._log(f"Supabase Cloud: Dongle '{serial_number}' ({operator_name}) tersimpan ke Cloud.", "SUCCESS")
                except Exception:
                    try:
                        # Fallback if Supabase column face_profile_hash is VARCHAR(128)
                        compact_hash = (
                            "LXV_SFACE_V3_SHA:" + hashlib.sha256((face_profile_hash or "").encode("utf-8")).hexdigest()[:48]
                            if (face_profile_hash and len(face_profile_hash) > 120)
                            else (face_profile_hash or "")
                        )
                        compact_payload = {**base_payload, "face_profile_hash": compact_hash}
                        self.supabase_client.table("authorized_dongles").upsert(compact_payload).execute()
                        self.cloud_online = True
                        self._log(f"Supabase Cloud: Dongle '{serial_number}' tersimpan (compact VARCHAR(128) mode).", "SUCCESS")
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
                        password_salt, password_hash, face_profile_hash,
                        face_embedding_front, face_embedding_left, face_embedding_right,
                        biometric_model, biometric_updated_at, is_active, registered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        serial_number,
                        operator_name,
                        badge_id,
                        token_signature,
                        password_salt,
                        password_hash,
                        face_profile_hash or "",
                        front_emb,
                        left_emb,
                        right_emb,
                        bio_model,
                        now_iso,
                        1 if is_active else 0,
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            self._sync_to_key_file(serial_number)
            return True

    def get_dongle(self, serial_number: str) -> Optional[Dict[str, Any]]:
        local_result: Optional[Dict[str, Any]] = None
        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                cur = conn.execute(
                    "SELECT * FROM authorized_dongles WHERE serial_number = ?",
                    (serial_number,),
                )
                row = cur.fetchone()
                if row:
                    local_result = dict(row)
                    local_result["is_active"] = bool(local_result.get("is_active", 0))
            finally:
                conn.close()

        # Check active dongle's classified.key as well if SQLite doesn't have face_profile_hash yet
        key_file = self.sqlite_path.parent / "classified.key"
        key_face = ""
        if key_file.exists():
            try:
                kd = json.loads(key_file.read_text(encoding="utf-8"))
                if str(kd.get("face_profile_hash") or "").startswith("LXV_SFACE_V3:"):
                    key_face = str(kd["face_profile_hash"])
            except Exception:
                pass

        if local_result:
            if not str(local_result.get("face_profile_hash") or "").startswith("LXV_SFACE_V3:") and key_face:
                local_result["face_profile_hash"] = key_face
            if str(local_result.get("face_profile_hash") or "").startswith("LXV_SFACE_V3:"):
                return local_result

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
                    cloud_row = dict(resp.data[0])
                    cloud_row["is_active"] = bool(cloud_row.get("is_active", False))
                    cloud_face = str(cloud_row.get("face_profile_hash") or "")
                    if not cloud_face.startswith("LXV_SFACE_V3:"):
                        if local_result and str(local_result.get("face_profile_hash") or "").startswith("LXV_SFACE_V3:"):
                            cloud_row["face_profile_hash"] = local_result["face_profile_hash"]
                        elif key_face:
                            cloud_row["face_profile_hash"] = key_face
                    return cloud_row
            except Exception as exc:
                self.cloud_online = False
                self._log(f"Supabase read timeout/error ({exc}), reading from SQLite.", "WARN")

        if local_result:
            return local_result
        return None

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
            finally:
                conn.close()
            self._sync_to_key_file(serial_number)
            return True

    def update_dongle_face_profile(self, serial_number: str, face_profile_hash: str) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        front_emb, left_emb, right_emb, bio_model = self._unpack_multipose_columns(face_profile_hash)
        extended_update = {
            "face_profile_hash": face_profile_hash,
            "face_embedding_front": front_emb,
            "face_embedding_left": left_emb,
            "face_embedding_right": right_emb,
            "biometric_model": bio_model,
            "biometric_updated_at": now_iso,
        }

        if self.supabase_client is None and self.supabase_url and self.supabase_key:
            self._init_supabase()

        if self.supabase_client is not None:
            try:
                res = self.supabase_client.table("authorized_dongles").update(
                    extended_update
                ).eq("serial_number", serial_number).execute()
                if res.data:
                    self.cloud_online = True
                    self._log(f"Supabase Cloud: Profil 3-Pose SFace berhasil disimpan untuk '{serial_number}'.", "SUCCESS")
            except Exception:
                try:
                    res = self.supabase_client.table("authorized_dongles").update(
                        {"face_profile_hash": face_profile_hash}
                    ).eq("serial_number", serial_number).execute()
                    if res.data:
                        self.cloud_online = True
                        self._log(f"Supabase Cloud: Profil wajah berhasil disimpan untuk dongle '{serial_number}'.", "SUCCESS")
                except Exception:
                    try:
                        # Fallback if Supabase column face_profile_hash is VARCHAR(128)
                        compact_hash = (
                            "LXV_SFACE_V3_SHA:" + hashlib.sha256((face_profile_hash or "").encode("utf-8")).hexdigest()[:48]
                            if (face_profile_hash and len(face_profile_hash) > 120)
                            else (face_profile_hash or "")
                        )
                        res = self.supabase_client.table("authorized_dongles").update(
                            {"face_profile_hash": compact_hash}
                        ).eq("serial_number", serial_number).execute()
                        self.cloud_online = True
                        self._log(f"Supabase Cloud: Profil wajah tersimpan (compact VARCHAR(128) digest) untuk '{serial_number}'.", "SUCCESS")
                    except Exception as exc:
                        self.cloud_online = False
                        self._log(f"Supabase face profile update failed ({exc}); saving to SQLite.", "WARN")

        target_serials = [serial_number]
        if serial_number in ("LXV-USB-484BC196", "LEXVAULT-DEV-DONGLE-001"):
            target_serials = ["LXV-USB-484BC196", "LEXVAULT-DEV-DONGLE-001"]

        with self._lock:
            conn = self._get_sqlite_conn()
            try:
                for tgt_s in target_serials:
                    conn.execute(
                        """
                        UPDATE authorized_dongles
                        SET face_profile_hash = ?,
                            face_embedding_front = ?,
                            face_embedding_left = ?,
                            face_embedding_right = ?,
                            biometric_model = ?,
                            biometric_updated_at = ?
                        WHERE serial_number = ?
                        """,
                        (
                            face_profile_hash,
                            front_emb,
                            left_emb,
                            right_emb,
                            bio_model,
                            now_iso,
                            tgt_s,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()
            self._sync_to_key_file(serial_number)
            return True

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

