"""Route and TCP reachability checks for the P-CSCF."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import socket
import time

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

    def log_route(self, pcscf_ip: str) -> RouteCheck:
        result = self.runner.run(["ip", "route", "get", pcscf_ip])
        output = result.stdout.strip()
        LOGGER.info("Route to P-CSCF: %s", output)
        return RouteCheck(pcscf_ip=pcscf_ip, interface="", output=output)

    def check_tcp_connect(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        timeout_seconds: float,
        attempts: int = 3,
    ) -> None:
        last_error: OSError | None = None
        for attempt in range(1, attempts + 1):
            sock = bindable_tcp_socket(local_ip, local_port)
            actual_local_ip, actual_local_port = sock.getsockname()
            try:
                sock.settimeout(timeout_seconds)
                sock.connect((remote_ip, remote_port))
                actual_local_ip, actual_local_port = sock.getsockname()
                LOGGER.info(
                    "TCP connect succeeded on attempt %s/%s: %s:%s -> %s:%s",
                    attempt,
                    attempts,
                    actual_local_ip,
                    actual_local_port,
                    remote_ip,
                    remote_port,
                )
                return
            except OSError as exc:
                last_error = exc
                LOGGER.warning(
                    "TCP connect attempt %s/%s failed: %s:%s -> %s:%s: %s",
                    attempt,
                    attempts,
                    actual_local_ip,
                    actual_local_port,
                    remote_ip,
                    remote_port,
                    exc,
                )
                if attempt < attempts:
                    time.sleep(0.5)
            finally:
                sock.close()

        raise NetworkError(
            f"TCP connect failed after {attempts} attempts: {local_ip}:<ephemeral> "
            f"-> {remote_ip}:{remote_port}: {last_error}"
        )
