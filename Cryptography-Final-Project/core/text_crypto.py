"""
Super-Encryption Engine (BAP Witness & Transcript Protection) for LexVault.
Pipeline:
- Encrypt: Plaintext (UTF-8) -> Full-ASCII Vigenere (byte shift mod 256) -> AES-256-CBC (PKCS7, 16-byte random IV) -> Base64
- Decrypt: Base64 -> AES-256-CBC Unpad -> Full-ASCII Vigenere Reverse (mod 256) -> Plaintext (UTF-8)
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


@dataclass
class SuperCryptoResult:
    ciphertext_b64: str
    iv_hex: str
    vigenere_hex_preview: str
    sha256_hash: str


class TextSuperCrypto:
    """
    Implements hybrid classical + modern symmetric Super-Encryption:
    Stage 1: Full-ASCII Vigenere Cipher operating on raw bytes (modulo 256).
    Stage 2: AES-256-CBC with PKCS#7 padding and a 16-byte cryptographically random IV.
    """

    BLOCK_SIZE = 16  # AES block size in bytes

    @staticmethod
    def derive_aes256_key(passphrase: str) -> bytes:
        """Derives a 256-bit (32-byte) key from any passphrase using SHA-256."""
        if not passphrase:
            raise ValueError("Kunci AES-256 tidak boleh kosong.")
        return hashlib.sha256(passphrase.encode("utf-8")).digest()

    @staticmethod
    def vigenere_encrypt_bytes(data: bytes, vigenere_key: str) -> bytes:
        """
        Applies Full-ASCII Vigenere byte shift modulo 256:
        C[i] = (P[i] + K[i mod len(K)]) mod 256
        """
        key_bytes = vigenere_key.encode("utf-8")
        if not key_bytes:
            raise ValueError("Kunci Vigenere tidak boleh kosong.")
        k_len = len(key_bytes)
        return bytes((b + key_bytes[i % k_len]) % 256 for i, b in enumerate(data))

    @staticmethod
    def vigenere_decrypt_bytes(data: bytes, vigenere_key: str) -> bytes:
        """
        Reverses Full-ASCII Vigenere byte shift modulo 256:
        P[i] = (C[i] - K[i mod len(K)]) mod 256
        """
        key_bytes = vigenere_key.encode("utf-8")
        if not key_bytes:
            raise ValueError("Kunci Vigenere tidak boleh kosong.")
        k_len = len(key_bytes)
        return bytes((b - key_bytes[i % k_len]) % 256 for i, b in enumerate(data))

    @classmethod
    def encrypt(
        cls,
        plaintext: str,
        vigenere_key: str,
        aes_passphrase: str,
    ) -> SuperCryptoResult:
        """
        Executes Super-Encryption:
        1. Encode plaintext as UTF-8 bytes.
        2. Encrypt bytes with Full-ASCII Vigenere (mod 256).
        3. Pad with PKCS#7 and encrypt with AES-256-CBC using a fresh 16-byte random IV.
        4. Prepend the 16-byte IV to the ciphertext and encode as Base64.
        """
        if not plaintext:
            raise ValueError("Plaintext tidak boleh kosong.")
        if not vigenere_key:
            raise ValueError("Kunci Vigenere wajib diisi.")
        if not aes_passphrase:
            raise ValueError("Passphrase AES-256 wajib diisi.")

        raw_bytes = plaintext.encode("utf-8")
        stage1_vigenere = cls.vigenere_encrypt_bytes(raw_bytes, vigenere_key)

        aes_key = cls.derive_aes256_key(aes_passphrase)
        iv = secrets.token_bytes(cls.BLOCK_SIZE)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        padded_data = pad(stage1_vigenere, cls.BLOCK_SIZE, style="pkcs7")
        aes_ciphertext = cipher.encrypt(padded_data)

        # Combine [16-byte IV + AES Ciphertext] into Base64 envelope
        envelope = iv + aes_ciphertext
        ciphertext_b64 = base64.b64encode(envelope).decode("ascii")
        sha256_digest = hashlib.sha256(envelope).hexdigest()

        return SuperCryptoResult(
            ciphertext_b64=ciphertext_b64,
            iv_hex=iv.hex(),
            vigenere_hex_preview=stage1_vigenere[:64].hex(),
            sha256_hash=sha256_digest,
        )

    @classmethod
    def decrypt(
        cls,
        ciphertext_b64: str,
        vigenere_key: str,
        aes_passphrase: str,
        explicit_iv_hex: Optional[str] = None,
    ) -> str:
        """
        Reverses Super-Encryption:
        1. Decode Base64 payload.
        2. Extract 16-byte IV (from envelope header or explicit_iv_hex).
        3. Decrypt AES-256-CBC and strip PKCS#7 padding.
        4. Reverse Full-ASCII Vigenere (mod 256) and decode UTF-8 plaintext.
        """
        if not ciphertext_b64 or not ciphertext_b64.strip():
            raise ValueError("Ciphertext Base64 tidak boleh kosong.")
        if not vigenere_key:
            raise ValueError("Kunci Vigenere wajib diisi.")
        if not aes_passphrase:
            raise ValueError("Passphrase AES-256 wajib diisi.")

        try:
            raw_envelope = base64.b64decode(ciphertext_b64.strip(), validate=True)
        except Exception as exc:
            raise ValueError(f"Format Base64 tidak valid: {exc}") from exc

        aes_key = cls.derive_aes256_key(aes_passphrase)

        if explicit_iv_hex and len(explicit_iv_hex.strip()) == 32:
            iv = bytes.fromhex(explicit_iv_hex.strip())
            # Check if envelope starts with that exact IV
            if raw_envelope.startswith(iv) and len(raw_envelope) > cls.BLOCK_SIZE:
                aes_ciphertext = raw_envelope[cls.BLOCK_SIZE :]
            else:
                aes_ciphertext = raw_envelope
        else:
            if len(raw_envelope) <= cls.BLOCK_SIZE:
                raise ValueError("Data terenkripsi terlalu pendek (IV + blok AES minimal 32 byte).")
            iv = raw_envelope[: cls.BLOCK_SIZE]
            aes_ciphertext = raw_envelope[cls.BLOCK_SIZE :]

        if len(aes_ciphertext) % cls.BLOCK_SIZE != 0:
            raise ValueError("Panjang ciphertext tidak sejajar dengan ukuran blok AES (16 byte).")

        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            decrypted_padded = cipher.decrypt(aes_ciphertext)
            stage1_vigenere = unpad(decrypted_padded, cls.BLOCK_SIZE, style="pkcs7")
        except ValueError as exc:
            raise ValueError(
                "Dekripsi AES-256-CBC gagal (Passphrase AES salah atau ciphertext telah dimodifikasi)."
            ) from exc

        plain_bytes = cls.vigenere_decrypt_bytes(stage1_vigenere, vigenere_key)
        try:
            return plain_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Dekripsi Vigenere menghasilkan byte non-UTF8 (Kunci Vigenere salah)."
            ) from exc

