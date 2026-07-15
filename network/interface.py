"""Linux IMS APN interface discovery."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import logging
import socket

from app.errors import NetworkError
from tools.command import CommandRunner

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    ipv4: str
    is_up: bool


class InterfaceResolver:
    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner(execute=True)

    def get_ipv4(self, interface: str) -> InterfaceInfo:
        result = self.runner.run(["ip", "-j", "addr", "show", "dev", interface])
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise NetworkError(f"Unable to parse ip addr output for {interface}") from exc

        if not payload:
            raise NetworkError(f"Interface not found: {interface}")

        entry = payload[0]
        is_up = "UP" in entry.get("flags", [])
        for addr in entry.get("addr_info", []):
            if addr.get("family") == "inet":
                ipv4 = addr.get("local")
                if not ipv4:
                    continue
                ipaddress.ip_address(ipv4)
                LOGGER.info("Resolved IMS interface %s IPv4: %s", interface, ipv4)
                return InterfaceInfo(name=interface, ipv4=ipv4, is_up=is_up)

        raise NetworkError(f"No IPv4 address found on interface: {interface}")


def bindable_tcp_socket(local_ip: str, local_port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((local_ip, local_port))
    except OSError as exc:
        sock.close()
        raise NetworkError(f"Unable to bind TCP socket to {local_ip}:{local_port}") from exc
    return sock
