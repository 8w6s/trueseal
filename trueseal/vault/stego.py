"""Steganography helpers for hiding vault data inside images."""

from __future__ import annotations

import hashlib
import random
import struct
from pathlib import Path

from PIL import Image

from ..crypto.cipher import AuthenticatedCipherError, create_cipher
from ..crypto.keygen import KeyGenerator


class SteganographyError(Exception):
    """Raised when steganography encoding or decoding fails."""


class Steganographer:
    """Hide and extract encrypted payloads from lossless images."""

    LOSSLESS_FORMATS = {".png", ".bmp", ".tiff", ".tif"}
    _MAX_SECRET_SIZE = 10 * 1024 * 1024
    _HEADER_SIZE = 20

    @staticmethod
    def _derive_seed(stego_key: str) -> int:
        return int.from_bytes(hashlib.sha256(stego_key.encode("utf-8")).digest()[:8], "big")

    @staticmethod
    def _get_pixel_mapping(width: int, height: int, channels: int, seed: int) -> list[int]:
        if channels not in {3, 4}:
            raise ValueError("Steganography only supports RGB or RGBA images.")

        rng = random.Random(seed)
        pixel_count = width * height
        channel_priority = [3, 2, 1, 0] if channels == 4 else [2, 1, 0]
        mapping: list[int] = []

        for channel in channel_priority[:channels]:
            channel_indices = list(range(pixel_count))
            rng.shuffle(channel_indices)
            mapping.extend(channel * pixel_count + pixel_index for pixel_index in channel_indices)

        return mapping

    @classmethod
    def _validate_cover_format(cls, cover_path: Path) -> None:
        if cover_path.suffix.lower() not in cls.LOSSLESS_FORMATS:
            allowed = ", ".join(sorted(cls.LOSSLESS_FORMATS))
            raise SteganographyError(f"Only lossless images are supported ({allowed}).")

    @staticmethod
    def _pack_bytes_to_bits(payload: bytes):
        for byte in payload:
            for bit_index in range(7, -1, -1):
                yield (byte >> bit_index) & 1

    @classmethod
    def hide_in_image(cls, cover_path, secret_bytes: bytes, output_path, stego_key: str) -> None:
        cover_path = Path(cover_path)
        output_path = Path(output_path)

        cls._validate_cover_format(cover_path)

        if len(secret_bytes) > cls._MAX_SECRET_SIZE:
            raise SteganographyError(
                f"Secret is too large for steganography ({len(secret_bytes)} bytes; max {cls._MAX_SECRET_SIZE} bytes)."
            )

        if not stego_key:
            raise SteganographyError("Stego key is required.")

        try:
            protection_key, salt = KeyGenerator.derive_key_from_password(stego_key)
            cipher = create_cipher("chacha20", protection_key.key_material)
            encrypted_payload = cipher.encrypt(secret_bytes)
            packed_payload = salt + struct.pack("<I", len(encrypted_payload)) + encrypted_payload

            with Image.open(cover_path) as source_image:
                image = source_image.convert("RGBA")

            width, height = image.size
            mapping = cls._get_pixel_mapping(width, height, 4, cls._derive_seed(stego_key))
            needed_bits = len(packed_payload) * 8

            if needed_bits > len(mapping):
                max_bytes = len(mapping) // 8
                raise SteganographyError(f"Payload is too large for this image. Maximum size is about {max_bytes} bytes.")

            pixels = image.load()
            bit_stream = cls._pack_bytes_to_bits(packed_payload)
            pixel_count = width * height

            for index in range(needed_bits):
                mapped_index = mapping[index]
                channel = mapped_index // pixel_count
                pixel_index = mapped_index % pixel_count
                x = pixel_index % width
                y = pixel_index // width

                pixel = list(pixels[x, y])
                pixel[channel] = (pixel[channel] & 0xFE) | next(bit_stream)
                pixels[x, y] = tuple(pixel)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            image.save(output_path)
        except Exception as exc:
            raise SteganographyError(f"Error in hide_in_image: {exc}") from exc

    @classmethod
    def extract_from_image(cls, stego_image_path, stego_key: str) -> bytes:
        stego_image_path = Path(stego_image_path)

        if not stego_key:
            raise SteganographyError("Stego key is required.")

        try:
            with Image.open(stego_image_path) as source_image:
                image = source_image.convert("RGBA")

            width, height = image.size
            mapping = cls._get_pixel_mapping(width, height, 4, cls._derive_seed(stego_key))
            pixels = image.load()
            pixel_count = width * height
            bit_cursor = 0

            def read_byte() -> int:
                nonlocal bit_cursor
                value = 0
                for _ in range(8):
                    if bit_cursor >= len(mapping):
                        raise SteganographyError("Image payload is truncated or the stego key is incorrect.")

                    mapped_index = mapping[bit_cursor]
                    bit_cursor += 1
                    channel = mapped_index // pixel_count
                    pixel_index = mapped_index % pixel_count
                    x = pixel_index % width
                    y = pixel_index // width
                    value = (value << 1) | (pixels[x, y][channel] & 1)

                return value

            salt = bytes(read_byte() for _ in range(16))
            encrypted_length = struct.unpack("<I", bytes(read_byte() for _ in range(4)))[0]

            if encrypted_length > (len(mapping) // 8) - cls._HEADER_SIZE:
                raise SteganographyError("Unexpected length field. The stego key may be wrong, or the image does not contain a vault.")

            encrypted_payload = bytes(read_byte() for _ in range(encrypted_length))

            protection_key, _ = KeyGenerator.derive_key_from_password(stego_key, salt=salt)
            cipher = create_cipher("chacha20", protection_key.key_material)

            try:
                return cipher.decrypt(encrypted_payload)
            except AuthenticatedCipherError as exc:
                raise SteganographyError(
                    "Authentication failed: the stego key is wrong or the image does not contain hidden data."
                ) from exc
        except SteganographyError:
            raise
        except Exception as exc:
            raise SteganographyError(f"LSB extraction failed: {exc}") from exc


__all__ = ["SteganographyError", "Steganographer"]
