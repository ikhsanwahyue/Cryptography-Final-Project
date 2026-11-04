"""
Binary File Locker (Forensic Asset Evidence Seal - Non-AES) for LexVault.
Uses stream cipher ChaCha20 (RFC 7539 / IETF 12-byte nonce) to encrypt and
decrypt arbitrary binary evidence files (.pdf, .docx, .zip, .mp4, .png, etc.)
into tamper-evident `.locked` containers.
Header structure: [NONCE (12 bytes)] + [CIPHERTEXT BYTES]
"""

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from Crypto.Cipher import ChaCha20


@dataclass
class FileLockResult:
    source_path: str
    output_path: str
    nonce_hex: str
    original_size_bytes: int
    locked_size_bytes: int
    sha256_hash: str


class BinaryFileLocker:
    """
    High-speed binary stream locker powered by ChaCha20 with a 96-bit (12-byte)
    cryptographically secure random nonce. Restores 100% bit-identical files on decryption.
    """

    NONCE_SIZE = 12  # 12-byte (96-bit) IETF ChaCha20 nonce
    CHUNK_SIZE = 1024 * 1024  # 1 MB streaming buffer

    @staticmethod
    def derive_chacha20_key(passphrase: str) -> bytes:
        """Derives a 256-bit (32-byte) ChaCha20 key via SHA-256."""
        if not passphrase:
            raise ValueError("Passphrase ChaCha20 tidak boleh kosong.")
        return hashlib.sha256(passphrase.encode("utf-8")).digest()

    @classmethod
    def encrypt_file(
        cls,
        input_path: str,
        passphrase: str,
        output_path: Optional[str] = None,
    ) -> FileLockResult:
        """
        Encrypts any binary file using ChaCha20 stream cipher and writes:
        [12-byte NONCE] + [ENCRYPTED STREAM] to `<filename>.locked`.
        Computes SHA-256 hash of the sealed `.locked` artifact for Chain of Custody.
        """
        src = Path(input_path).resolve()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"File bukti fisik tidak ditemukan: {src}")

        dst = Path(output_path).resolve() if output_path else Path(f"{src}.locked")
        key = cls.derive_chacha20_key(passphrase)
        nonce = secrets.token_bytes(cls.NONCE_SIZE)
        cipher = ChaCha20.new(key=key, nonce=nonce)

        sha256_hasher = hashlib.sha256()
        original_size = src.stat().st_size

        with src.open("rb") as f_in, dst.open("wb") as f_out:
            # Write 12-byte nonce header first
            f_out.write(nonce)
            sha256_hasher.update(nonce)

            while True:
                chunk = f_in.read(cls.CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)
                sha256_hasher.update(encrypted_chunk)

        locked_size = dst.stat().st_size
        return FileLockResult(
            source_path=str(src),
            output_path=str(dst),
            nonce_hex=nonce.hex(),
            original_size_bytes=original_size,
            locked_size_bytes=locked_size,
            sha256_hash=sha256_hasher.hexdigest(),
        )

    @classmethod
    def decrypt_file(
        cls,
        locked_path: str,
        passphrase: str,
        output_path: Optional[str] = None,
    ) -> FileLockResult:
        """
        Reads a `.locked` file, extracts the first 12 bytes as the ChaCha20 nonce,
        and decrypts the remaining binary stream back into its original format.
        """
        src = Path(locked_path).resolve()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"File .locked tidak ditemukan: {src}")

        locked_size = src.stat().st_size
        if locked_size < cls.NONCE_SIZE:
            raise ValueError(
                f"File tidak valid atau rusak: ukuran ({locked_size} byte) kurang dari header nonce 12 byte."
            )

        if output_path:
            dst = Path(output_path).resolve()
        else:
            if src.name.endswith(".locked"):
                restored_name = src.name[: -len(".locked")]
                dst = src.parent / f"restored_{restored_name}"
            else:
                dst = src.parent / f"restored_{src.name}"

        key = cls.derive_chacha20_key(passphrase)
        sha256_hasher = hashlib.sha256()

        with src.open("rb") as f_in, dst.open("wb") as f_out:
            nonce = f_in.read(cls.NONCE_SIZE)
            if len(nonce) != cls.NONCE_SIZE:
                raise ValueError("Gagal membaca 12-byte nonce dari header file.")

            cipher = ChaCha20.new(key=key, nonce=nonce)
            while True:
                chunk = f_in.read(cls.CHUNK_SIZE)
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                f_out.write(decrypted_chunk)
                sha256_hasher.update(decrypted_chunk)

        restored_size = dst.stat().st_size
        return FileLockResult(
            source_path=str(src),
            output_path=str(dst),
            nonce_hex=nonce.hex(),
            original_size_bytes=restored_size,
            locked_size_bytes=locked_size,
            sha256_hash=sha256_hasher.hexdigest(),
        )

