"""AMR-WB storage frame and RFC 4867 octet-aligned payload conversion."""

from __future__ import annotations

from dataclasses import dataclass

from app.errors import MediaError

AMRWB_MAGIC = b"#!AMR-WB\n"

# AMR-WB storage frame payload sizes excluding the one-byte frame header.
AMRWB_SPEECH_SIZES = {
    0: 17,
    1: 23,
    2: 32,
    3: 36,
    4: 40,
    5: 46,
    6: 50,
    7: 58,
    8: 60,
    9: 5,
}

AMRWB_SPEECH_BITS = {
    0: 132,
    1: 177,
    2: 253,
    3: 285,
    4: 317,
    5: 365,
    6: 397,
    7: 461,
    8: 477,
    9: 40,
}


@dataclass(frozen=True)
class AmrWbFrame:
    ft: int
    quality: bool
    speech: bytes

    def to_storage_frame(self) -> bytes:
        header = ((self.ft & 0x0F) << 3) | (0x04 if self.quality else 0)
        return bytes([header]) + self.speech


def storage_frame_size(frame_header: int) -> int:
    ft = (frame_header >> 3) & 0x0F
    if ft not in AMRWB_SPEECH_SIZES:
        raise MediaError(f"Unsupported AMR-WB frame type: {ft}")
    return 1 + AMRWB_SPEECH_SIZES[ft]


def parse_storage_frame(data: bytes) -> AmrWbFrame:
    if not data:
        raise MediaError("Empty AMR-WB storage frame")
    header = data[0]
    ft = (header >> 3) & 0x0F
    quality = bool(header & 0x04)
    expected = storage_frame_size(header)
    if len(data) != expected:
        raise MediaError(f"Invalid AMR-WB frame size for FT={ft}: {len(data)} != {expected}")
    return AmrWbFrame(ft=ft, quality=quality, speech=data[1:])


def frame_to_rtp_payload(frame: AmrWbFrame, cmr: int = 15, *, octet_aligned: bool = True) -> bytes:
    if octet_aligned:
        # RFC 4867 octet-aligned: CMR octet, one TOC octet, then speech data.
        cmr_octet = (cmr & 0x0F) << 4
        toc = ((frame.ft & 0x0F) << 3) | (0x04 if frame.quality else 0)
        return bytes([cmr_octet, toc]) + frame.speech

    speech_bits = AMRWB_SPEECH_BITS.get(frame.ft)
    if speech_bits is None:
        raise MediaError(f"Unsupported AMR-WB frame type: {frame.ft}")
    bits = _int_to_bits(cmr & 0x0F, 4)
    # Bandwidth-efficient TOC: F bit, FT, Q. Single-frame packet uses F=0.
    bits.extend([0])
    bits.extend(_int_to_bits(frame.ft & 0x0F, 4))
    bits.extend([1 if frame.quality else 0])
    bits.extend(_bytes_to_bits(frame.speech, speech_bits))
    return _bits_to_bytes(bits)


def rtp_payload_to_frame(payload: bytes, *, octet_aligned: bool = True) -> AmrWbFrame:
    if not octet_aligned:
        return _bandwidth_efficient_payload_to_frame(payload)

    if len(payload) < 2:
        raise MediaError("AMR-WB RTP payload is too short")
    toc = payload[1]
    ft = (toc >> 3) & 0x0F
    quality = bool(toc & 0x04)
    expected_speech = AMRWB_SPEECH_SIZES.get(ft)
    if expected_speech is None:
        raise MediaError(f"Unsupported AMR-WB RTP frame type: {ft}")
    speech = payload[2:]
    if len(speech) != expected_speech:
        raise MediaError(f"Invalid AMR-WB RTP speech size for FT={ft}: {len(speech)}")
    return AmrWbFrame(ft=ft, quality=quality, speech=speech)


def _bandwidth_efficient_payload_to_frame(payload: bytes) -> AmrWbFrame:
    bits = _bytes_to_bits(payload, len(payload) * 8)
    if len(bits) < 10:
        raise MediaError("AMR-WB bandwidth-efficient RTP payload is too short")
    offset = 4  # CMR
    f_bit = bits[offset]
    offset += 1
    if f_bit:
        raise MediaError("Multiple AMR-WB frames per RTP packet are not supported")
    ft = _bits_to_int(bits[offset : offset + 4])
    offset += 4
    quality = bool(bits[offset])
    offset += 1
    speech_bits = AMRWB_SPEECH_BITS.get(ft)
    if speech_bits is None:
        raise MediaError(f"Unsupported AMR-WB RTP frame type: {ft}")
    expected_payload_bytes = (offset + speech_bits + 7) // 8
    if len(payload) != expected_payload_bytes:
        raise MediaError(
            f"Invalid AMR-WB bandwidth-efficient payload size for FT={ft}: "
            f"{len(payload)} != {expected_payload_bytes}"
        )
    speech = _bits_to_bytes(bits[offset : offset + speech_bits])
    expected_speech = AMRWB_SPEECH_SIZES[ft]
    if len(speech) != expected_speech:
        raise MediaError(f"Invalid unpacked AMR-WB speech size for FT={ft}: {len(speech)}")
    return AmrWbFrame(ft=ft, quality=quality, speech=speech)


def _bytes_to_bits(data: bytes, bit_count: int) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
            if len(bits) == bit_count:
                return bits
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | (bit & 1)
        value <<= max(0, 8 - len(bits[offset : offset + 8]))
        out.append(value)
    return bytes(out)


def _int_to_bits(value: int, width: int) -> list[int]:
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def _bits_to_int(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | (bit & 1)
    return value
