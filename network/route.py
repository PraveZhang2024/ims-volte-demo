"""Route and TCP reachability checks for the P-CSCF."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import socket

from app.errors import NetworkError
from network.interface import bindable_tcp_socket
from tools.command import CommandRunner

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RouteCheck:
    pcscf_ip: str
    interface: str
    output: str


class RouteChecker:
    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner(execute=True)

    def check_route(self, pcscf_ip: str, interface: str) -> RouteCheck:
        result = self.runner.run(["ip", "route", "get", pcscf_ip])
        output = result.stdout.strip()
        if interface not in output:
            raise NetworkError(
                f"Route to P-CSCF {pcscf_ip} does not appear to use {interface}: {output}"
            )
        LOGGER.info("Route to P-CSCF uses %s: %s", interface, output)
        return RouteCheck(pcscf_ip=pcscf_ip, interface=interface, output=output)

    def check_tcp_connect(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        timeout_seconds: float,
    ) -> None:
        sock = bindable_tcp_socket(local_ip, local_port)
        try:
            sock.settimeout(timeout_seconds)
            sock.connect((remote_ip, remote_port))
            LOGGER.info(
                "TCP connect succeeded: %s:%s -> %s:%s",
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            )
        except OSError as exc:
            raise NetworkError(
                f"TCP connect failed: {local_ip}:{local_port} -> {remote_ip}:{remote_port}"
            ) from exc
        finally:
            sock.close()
