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


def frame_to_rtp_payload(frame: AmrWbFrame, cmr: int = 15) -> bytes:
    # RFC 4867 octet-aligned: CMR octet, one TOC octet, then speech data.
    cmr_octet = (cmr & 0x0F) << 4
    toc = ((frame.ft & 0x0F) << 3) | (0x04 if frame.quality else 0)
    return bytes([cmr_octet, toc]) + frame.speech


def rtp_payload_to_frame(payload: bytes) -> AmrWbFrame:
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
