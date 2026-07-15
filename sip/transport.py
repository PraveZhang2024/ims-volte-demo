"""SIP over TCP transport."""

from __future__ import annotations

import logging
import socket

from app.errors import SipError
from sip.message import SipMessage
from sip.parser import SipStreamParser

LOGGER = logging.getLogger(__name__)


class SipTcpTransport:
    def __init__(
        self,
        *,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        timeout_seconds: float,
        dump_sip: bool = True,
    ) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.timeout_seconds = timeout_seconds
        self.dump_sip = dump_sip
        self._sock: socket.socket | None = None
        self._parser = SipStreamParser()

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout_seconds)
            sock.bind((self.local_ip, self.local_port))
            sock.connect((self.remote_ip, self.remote_port))
        except OSError as exc:
            sock.close()
            raise SipError(
                f"SIP TCP connect failed: {self.local_ip}:{self.local_port} -> "
                f"{self.remote_ip}:{self.remote_port}"
            ) from exc
        self._sock = sock
        LOGGER.info(
            "SIP TCP connected: %s:%s -> %s:%s",
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
        )

    def send(self, message: SipMessage) -> None:
        sock = self._require_socket()
        payload = message.to_bytes()
        if self.dump_sip:
            LOGGER.info("SIP SEND\n%s", payload.decode("utf-8", errors="replace"))
        sock.sendall(payload)

    def receive(self) -> SipMessage:
        sock = self._require_socket()
        while True:
            data = sock.recv(65535)
            if not data:
                raise SipError("SIP TCP connection closed by peer")
            messages = self._parser.feed(data)
            if messages:
                message = messages[0]
                if self.dump_sip:
                    LOGGER.info("SIP RECV\n%s", message.to_bytes().decode("utf-8", errors="replace"))
                return message

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _require_socket(self) -> socket.socket:
        if self._sock is None:
            raise SipError("SIP TCP transport is not connected")
        return self._sock
