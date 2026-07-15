"""AMR-WB RTP sender."""

from __future__ import annotations

import logging
from pathlib import Path
import secrets
import socket
import threading
import time

from app.config import AppConfig
from media.amrwb_file import AmrWbFileReader
from media.amrwb_payload import frame_to_rtp_payload
from media.rtp_packet import RtpPacket
from sdp.parser import RemoteMedia

LOGGER = logging.getLogger(__name__)


class RtpSender:
    def __init__(
        self,
        *,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        payload_type: int,
        ptime_ms: int,
        timestamp_step: int,
        amr_path: Path,
    ) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.payload_type = payload_type
        self.ptime_ms = ptime_ms
        self.timestamp_step = timestamp_step
        self.amr_path = amr_path
        self.sequence = secrets.randbelow(0xFFFF)
        self.timestamp = secrets.randbelow(0xFFFFFFFF)
        self.ssrc = secrets.randbits(32)
        self.packets_sent = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @classmethod
    def from_config(cls, config: AppConfig, local_ip: str, remote_media: RemoteMedia) -> "RtpSender":
        return cls(
            local_ip=local_ip,
            local_port=config.network.local_rtp_port,
            remote_ip=remote_media.ip,
            remote_port=remote_media.port,
            payload_type=remote_media.payload_type,
            ptime_ms=config.media.ptime_ms,
            timestamp_step=int(config.media.clock_rate * config.media.ptime_ms / 1000),
            amr_path=config.base_dir / config.media.send_file,
        )

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="rtp-sender", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        reader = AmrWbFileReader(self.amr_path, loop=True)
        try:
            sock.bind((self.local_ip, self.local_port))
            interval = self.ptime_ms / 1000.0
            next_send = time.monotonic()
            while not self._stop.is_set():
                frame = reader.read_frame()
                if frame is None:
                    break
                payload = frame_to_rtp_payload(frame)
                packet = RtpPacket(
                    payload_type=self.payload_type,
                    sequence=self.sequence,
                    timestamp=self.timestamp,
                    ssrc=self.ssrc,
                    payload=payload,
                    marker=self.packets_sent == 0,
                )
                sock.sendto(packet.to_bytes(), (self.remote_ip, self.remote_port))
                self.packets_sent += 1
                self.sequence = (self.sequence + 1) & 0xFFFF
                self.timestamp = (self.timestamp + self.timestamp_step) & 0xFFFFFFFF
                next_send += interval
                time.sleep(max(0, next_send - time.monotonic()))
        finally:
            reader.close()
            sock.close()
            LOGGER.info("RTP sender stopped after %s packets", self.packets_sent)
