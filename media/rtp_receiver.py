"""AMR-WB RTP receiver."""

from __future__ import annotations

import logging
from pathlib import Path
import socket
import threading

from app.config import AppConfig
from app.errors import MediaError
from media.amrwb_file import AmrWbFileWriter
from media.amrwb_payload import rtp_payload_to_frame
from media.rtp_packet import RtpPacket
from sdp.parser import RemoteMedia

LOGGER = logging.getLogger(__name__)


class RtpReceiver:
    def __init__(
        self,
        *,
        local_ip: str,
        local_port: int,
        payload_type: int,
        output_path: Path,
        octet_aligned: bool,
        sock: socket.socket | None = None,
        close_socket_on_stop: bool = False,
    ) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.payload_type = payload_type
        self.output_path = output_path
        self.octet_aligned = octet_aligned
        self._sock = sock
        self._owns_socket = sock is None
        self._close_socket_on_stop = close_socket_on_stop
        self.packets_received = 0
        self.frames_written = 0
        self.frames_discarded = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @classmethod
    def from_config(
        cls,
        config: AppConfig,
        local_ip: str,
        remote_media: RemoteMedia,
        sock: socket.socket | None = None,
        close_socket_on_stop: bool = False,
    ) -> "RtpReceiver":
        return cls(
            local_ip=local_ip,
            local_port=config.network.local_rtp_port,
            payload_type=remote_media.payload_type,
            output_path=config.base_dir / config.media.receive_file,
            octet_aligned=remote_media.octet_aligned,
            sock=sock,
            close_socket_on_stop=close_socket_on_stop,
        )

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="rtp-receiver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        sock = self._sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        writer = AmrWbFileWriter(self.output_path)
        try:
            if self._owns_socket:
                sock.bind((self.local_ip, self.local_port))
            sock.settimeout(0.5)
            LOGGER.info(
                "RTP receiver started: %s:%s PT=%s octet_align=%s output=%s",
                self.local_ip,
                self.local_port,
                self.payload_type,
                self.octet_aligned,
                self.output_path,
            )
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    packet = RtpPacket.from_bytes(data)
                except MediaError as exc:
                    self.frames_discarded += 1
                    LOGGER.warning("Discarding invalid RTP packet from %s:%s: %s", addr[0], addr[1], exc)
                    continue
                self.packets_received += 1
                if self.packets_received == 1 or self.packets_received % 100 == 0:
                    LOGGER.info(
                        "RTP received packets=%s from=%s:%s PT=%s seq=%s timestamp=%s payload_bytes=%s",
                        self.packets_received,
                        addr[0],
                        addr[1],
                        packet.payload_type,
                        packet.sequence,
                        packet.timestamp,
                        len(packet.payload),
                    )
                try:
                    frame = self._decode_packet_payload(packet)
                except MediaError as exc:
                    self.frames_discarded += 1
                    LOGGER.warning(
                        "Discarding RTP payload PT=%s seq=%s timestamp=%s bytes=%s: %s",
                        packet.payload_type,
                        packet.sequence,
                        packet.timestamp,
                        len(packet.payload),
                        exc,
                    )
                    continue
                if frame is None:
                    continue
                writer.write_frame(frame)
                self.frames_written += 1
        finally:
            writer.close()
            if self._owns_socket or self._close_socket_on_stop:
                sock.close()
            LOGGER.info(
                "RTP receiver stopped after %s packets, %s frames, %s discarded",
                self.packets_received,
                self.frames_written,
                self.frames_discarded,
            )

    def _decode_packet_payload(self, packet: RtpPacket):
        if packet.payload_type == self.payload_type:
            return rtp_payload_to_frame(packet.payload, octet_aligned=self.octet_aligned)

        if 96 <= packet.payload_type <= 127:
            frame = rtp_payload_to_frame(packet.payload, octet_aligned=self.octet_aligned)
            LOGGER.warning(
                "Learned AMR-WB RTP payload type from incoming packet: old_PT=%s new_PT=%s octet_align=%s",
                self.payload_type,
                packet.payload_type,
                self.octet_aligned,
            )
            self.payload_type = packet.payload_type
            return frame

        LOGGER.debug("Ignoring RTP payload type %s, expected %s", packet.payload_type, self.payload_type)
        return None
