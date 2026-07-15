"""RTP packet encode/decode for a single SSRC media stream."""

from __future__ import annotations

from dataclasses import dataclass
import struct

from app.errors import MediaError

RTP_HEADER = struct.Struct("!BBHII")


@dataclass(frozen=True)
class RtpPacket:
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes
    marker: bool = False

    def to_bytes(self) -> bytes:
        first = 0x80
        second = (0x80 if self.marker else 0) | (self.payload_type & 0x7F)
        header = RTP_HEADER.pack(
            first,
            second,
            self.sequence & 0xFFFF,
            self.timestamp & 0xFFFFFFFF,
            self.ssrc & 0xFFFFFFFF,
        )
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "RtpPacket":
        if len(data) < RTP_HEADER.size:
            raise MediaError("RTP packet is shorter than the fixed header")
        first, second, sequence, timestamp, ssrc = RTP_HEADER.unpack(data[: RTP_HEADER.size])
        version = first >> 6
        if version != 2:
            raise MediaError(f"Unsupported RTP version: {version}")
        csrc_count = first & 0x0F
        header_len = RTP_HEADER.size + csrc_count * 4
        if len(data) < header_len:
            raise MediaError("RTP packet is shorter than its CSRC list")
        return cls(
            payload_type=second & 0x7F,
            marker=bool(second & 0x80),
            sequence=sequence,
            timestamp=timestamp,
            ssrc=ssrc,
            payload=data[header_len:],
        )
