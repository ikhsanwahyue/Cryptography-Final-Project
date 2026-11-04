"""
LSB (Least Significant Bit) Lossless PNG Steganography Engine for LexVault.
Embeds a 32-bit big-endian byte-length header followed by the secret payload bits
across the R, G, B channels of a lossless PNG carrier image via Pillow.
"""

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from PIL import Image


@dataclass
class StegoEmbedResult:
    carrier_path: str
    output_path: str
    payload_bytes_len: int
    total_bits_embedded: int
    capacity_bits: int
    utilization_percent: float
    sha256_hash: str


class StegoEngine:
    """
    Bitwise Least Significant Bit (LSB) Steganography on lossless PNG images.
    Format: [32-bit unsigned int payload length (in bytes)] + [UTF-8 payload bits]
    distributed sequentially across R, G, B channel LSBs of each pixel.
    """

    HEADER_BYTES = 4
    HEADER_BITS = HEADER_BYTES * 8  # 32 bits

    @staticmethod
    def calculate_capacity(image_path: str) -> Tuple[int, int]:
        """
        Returns (max_bits, max_payload_bytes) for a given image.
        Each pixel provides 3 bits of capacity (1 bit per R, G, B channel).
        """
        with Image.open(image_path) as img:
            width, height = img.size
        total_bits = width * height * 3
        max_bytes = max(0, (total_bits - StegoEngine.HEADER_BITS) // 8)
        return total_bits, max_bytes

    @classmethod
    def embed_message(
        cls,
        carrier_image_path: str,
        secret_message: str,
        output_image_path: str,
    ) -> StegoEmbedResult:
        """
        Embeds `secret_message` into `carrier_image_path` and saves as a lossless PNG
        at `output_image_path`.
        """
        src = Path(carrier_image_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Citra carrier tidak ditemukan: {src}")
        if not secret_message:
            raise ValueError("Pesan rahasia steganografi tidak boleh kosong.")

        payload_bytes = secret_message.encode("utf-8")
        payload_len = len(payload_bytes)
        header_bytes = struct.pack(">I", payload_len)  # 32-bit unsigned big-endian integer
        full_stream = header_bytes + payload_bytes

        # Convert byte stream to list of bits (MSB to LSB per byte)
        bits = [
            (byte_val >> bit_idx) & 1
            for byte_val in full_stream
            for bit_idx in range(7, -1, -1)
        ]
        total_bits_to_embed = len(bits)

        with Image.open(src) as img:
            has_alpha = img.mode == "RGBA"
            work_img = img.convert("RGBA" if has_alpha else "RGB")
            width, height = work_img.size
            capacity_bits = width * height * 3

            if total_bits_to_embed > capacity_bits:
                max_bytes = (capacity_bits - cls.HEADER_BITS) // 8
                raise ValueError(
                    f"Pesan terlalu besar ({payload_len} byte) untuk ukuran citra {width}x{height} "
                    f"(kapasitas maksimum: {max_bytes} byte)."
                )

            pixels = list(work_img.getdata())
            new_pixels = []
            bit_cursor = 0

            for px in pixels:
                if bit_cursor >= total_bits_to_embed:
                    new_pixels.append(px)
                    continue

                channels = list(px)
                # Modify LSB of R, G, B (indices 0, 1, 2)
                for c_idx in range(3):
                    if bit_cursor < total_bits_to_embed:
                        channels[c_idx] = (channels[c_idx] & ~1) | bits[bit_cursor]
                        bit_cursor += 1

                new_pixels.append(tuple(channels))

            out_img = Image.new(work_img.mode, (width, height))
            out_img.putdata(new_pixels)

            dst = Path(output_image_path).resolve()
            if dst.suffix.lower() != ".png":
                dst = dst.with_suffix(".png")
            out_img.save(str(dst), format="PNG", compress_level=6)

        file_hash = hashlib.sha256(dst.read_bytes()).hexdigest()
        utilization = (total_bits_to_embed / capacity_bits) * 100.0 if capacity_bits else 0.0

        return StegoEmbedResult(
            carrier_path=str(src),
            output_path=str(dst),
            payload_bytes_len=payload_len,
            total_bits_embedded=total_bits_to_embed,
            capacity_bits=capacity_bits,
            utilization_percent=round(utilization, 4),
            sha256_hash=file_hash,
        )

    @classmethod
    def extract_message(cls, stego_image_path: str) -> str:
        """
        Extracts the hidden UTF-8 message from a lossless PNG stego image by reading
        the 32-bit length header first, then reconstructing the exact byte payload.
        """
        src = Path(stego_image_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Citra steganografi tidak ditemukan: {src}")

        with Image.open(src) as img:
            work_img = img.convert("RGB")
            width, height = work_img.size
            capacity_bits = width * height * 3
            if capacity_bits < cls.HEADER_BITS:
                raise ValueError("Citra terlalu kecil untuk memuat header LSB 32-bit.")

            pixels = list(work_img.getdata())

        # Step 1: Extract first 32 bits for byte length header
        header_bits = []
        for px in pixels:
            for c_idx in range(3):
                header_bits.append(px[c_idx] & 1)
                if len(header_bits) == cls.HEADER_BITS:
                    break
            if len(header_bits) == cls.HEADER_BITS:
                break

        header_val = 0
        for b in header_bits:
            header_val = (header_val << 1) | b

        max_possible_bytes = (capacity_bits - cls.HEADER_BITS) // 8
        if header_val <= 0 or header_val > max_possible_bytes:
            raise ValueError(
                f"Tidak ditemukan payload steganografi LexVault yang valid pada citra ini "
                f"(header terdeteksi: {header_val} byte, kapasitas maks: {max_possible_bytes} byte)."
            )

        total_bits_needed = cls.HEADER_BITS + (header_val * 8)
        extracted_bits = []
        for px in pixels:
            for c_idx in range(3):
                extracted_bits.append(px[c_idx] & 1)
                if len(extracted_bits) == total_bits_needed:
                    break
            if len(extracted_bits) == total_bits_needed:
                break

        payload_bits = extracted_bits[cls.HEADER_BITS :]
        payload_bytes = bytearray()
        for i in range(0, len(payload_bits), 8):
            byte_chunk = payload_bits[i : i + 8]
            val = 0
            for b in byte_chunk:
                val = (val << 1) | b
            payload_bytes.append(val)

        try:
            return bytes(payload_bytes).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Data LSB berhasil diekstrak tetapi bukan teks UTF-8 valid (citra mungkin terkompresi/rusak)."
            ) from exc

