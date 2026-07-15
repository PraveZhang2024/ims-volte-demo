"""Minimal SIP message model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

CRLF = "\r\n"


@dataclass
class SipMessage:
    start_line: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    def add_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def get_all(self, name: str) -> list[str]:
        lower = name.lower()
        return [value for key, value in self.headers if key.lower() == lower]

    def get(self, name: str, default: str | None = None) -> str | None:
        values = self.get_all(name)
        return values[-1] if values else default

    @property
    def is_response(self) -> bool:
        return self.start_line.upper().startswith("SIP/2.0")

    @property
    def status_code(self) -> int | None:
        if not self.is_response:
            return None
        parts = self.start_line.split(maxsplit=2)
        if len(parts) < 2:
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None

    @property
    def method(self) -> str | None:
        if self.is_response:
            cseq = self.get("CSeq", "")
            parts = cseq.split()
            return parts[1] if len(parts) >= 2 else None
        return self.start_line.split(maxsplit=1)[0]

    def with_content_length(self) -> "SipMessage":
        filtered = [(k, v) for k, v in self.headers if k.lower() != "content-length"]
        self.headers = filtered
        self.headers.append(("Content-Length", str(len(self.body.encode("utf-8")))))
        return self

    def to_bytes(self) -> bytes:
        self.with_content_length()
        lines = [self.start_line]
        lines.extend(f"{name}: {value}" for name, value in self.headers)
        text = CRLF.join(lines) + CRLF + CRLF + self.body
        return text.encode("utf-8")


def format_params(params: dict[str, str | int | bool | None]) -> str:
    chunks: list[str] = []
    for key, value in params.items():
        if value is None:
            continue
        if value is True:
            chunks.append(key)
        elif value is False:
            continue
        else:
            chunks.append(f"{key}={value}")
    return ";".join(chunks)


def join_header_values(values: Iterable[str]) -> str:
    return ", ".join(value for value in values if value)
