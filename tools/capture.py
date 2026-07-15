"""tcpdump helper for optional lab packet captures."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import subprocess


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
        self._process = subprocess.Popen(
            ["tcpdump", "-i", self.interface, "-w", str(self.path), "sip or esp or rtp or rtcp"],
            text=True,
        )

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        self._process.wait(timeout=5)
        self._process = None
