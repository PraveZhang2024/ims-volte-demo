"""tcpdump helper for optional lab packet captures."""

from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
import subprocess

LOGGER = logging.getLogger(__name__)


class TcpdumpCapture:
    def __init__(self, *, interface: str, output_dir: Path, enabled: bool) -> None:
        self.interface = interface
        self.output_dir = output_dir
        self.enabled = enabled
        self.path: Path | None = None
        self._process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if not self.enabled:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = self.output_dir / f"ims-demo-{stamp}.pcap"
        command = [
            "tcpdump",
            "-i",
            self.interface or "any",
            "-s",
            "0",
            "-w",
            str(self.path),
            "tcp port 5060 or esp or udp or icmp",
        ]
        LOGGER.info("Starting tcpdump capture: %s", " ".join(command))
        self._process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            LOGGER.error("tcpdump exited immediately: %s", stderr.strip())

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        self._process.wait(timeout=5)
        if self.path:
            LOGGER.info("Stopped tcpdump capture: %s", self.path)
        self._process = None
