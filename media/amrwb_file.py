"""AMR-WB file readers and writers."""

from __future__ import annotations

from pathlib import Path

from app.errors import MediaError
from media.amrwb_payload import AMRWB_MAGIC, AmrWbFrame, parse_storage_frame, storage_frame_size


class AmrWbFileReader:
    def __init__(self, path: str | Path, *, loop: bool = True) -> None:
        self.path = Path(path)
        self.loop = loop
        self._handle = self.path.open("rb")
        magic = self._handle.read(len(AMRWB_MAGIC))
        if magic != AMRWB_MAGIC:
            raise MediaError(f"Not an AMR-WB storage file: {self.path}")

    def read_frame(self) -> AmrWbFrame | None:
        header = self._handle.read(1)
        if not header:
            if not self.loop:
                return None
            self._handle.seek(len(AMRWB_MAGIC))
            header = self._handle.read(1)
            if not header:
                return None
        size = storage_frame_size(header[0])
        rest = self._handle.read(size - 1)
        if len(rest) != size - 1:
            raise MediaError(f"Truncated AMR-WB frame in {self.path}")
        return parse_storage_frame(header + rest)

    def close(self) -> None:
        self._handle.close()


class AmrWbFileWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("wb")
        self._handle.write(AMRWB_MAGIC)

    def write_frame(self, frame: AmrWbFrame) -> None:
        self._handle.write(frame.to_storage_frame())

    def close(self) -> None:
        self._handle.close()
