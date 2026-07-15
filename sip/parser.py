"""SIP parser and TCP stream splitter."""

from __future__ import annotations

import re

from app.errors import SipError
from sip.message import SipMessage

HEADER_END = b"\r\n\r\n"
CONTENT_LENGTH_RE = re.compile(r"^(content-length|l)\s*:\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


class SipStreamParser:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[SipMessage]:
        self._buffer.extend(data)
        messages: list[SipMessage] = []

        while True:
            header_end = self._buffer.find(HEADER_END)
            if header_end < 0:
                break

            header_bytes = bytes(self._buffer[:header_end]).decode("utf-8", errors="replace")
            content_length = _content_length(header_bytes)
            total_length = header_end + len(HEADER_END) + content_length
            if len(self._buffer) < total_length:
                break

            raw = bytes(self._buffer[:total_length])
            del self._buffer[:total_length]
            messages.append(parse_sip_message(raw))

        return messages


def parse_sip_message(raw: bytes | str) -> SipMessage:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    header_text, sep, body = text.partition("\r\n\r\n")
    if not sep:
        raise SipError("SIP message is missing header/body separator")

    lines = header_text.split("\r\n")
    if not lines or not lines[0].strip():
        raise SipError("SIP message has no start line")

    message = SipMessage(start_line=lines[0].strip(), body=body)
    current_name: str | None = None
    current_value: list[str] = []

    def flush_header() -> None:
        if current_name is not None:
            message.add_header(current_name, " ".join(current_value).strip())

    for line in lines[1:]:
        if line.startswith((" ", "\t")):
            if current_name is None:
                raise SipError("SIP folded header without a previous header")
            current_value.append(line.strip())
            continue

        flush_header()
        if ":" not in line:
            raise SipError(f"Invalid SIP header line: {line}")
        name, value = line.split(":", 1)
        current_name = name.strip()
        current_value = [value.strip()]

    flush_header()
    return message


def parse_name_addr_params(value: str) -> tuple[str, dict[str, str | bool]]:
    main, *param_parts = value.split(";")
    params: dict[str, str | bool] = {}
    for part in param_parts:
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            params[key.strip().lower()] = val.strip().strip('"')
        else:
            params[part.strip().lower()] = True
    return main.strip(), params


def parse_auth_params(value: str) -> dict[str, str]:
    _, _, rest = value.partition(" ")
    source = rest or value
    params: dict[str, str] = {}
    token = ""
    in_quote = False
    parts: list[str] = []

    for char in source:
        if char == '"':
            in_quote = not in_quote
        if char == "," and not in_quote:
            parts.append(token)
            token = ""
        else:
            token += char
    if token:
        parts.append(token)

    for part in parts:
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        params[key.strip().lower()] = val.strip().strip('"')
    return params


def _content_length(header_text: str) -> int:
    for line in header_text.split("\r\n"):
        match = CONTENT_LENGTH_RE.match(line)
        if match:
            return int(match.group(2))
    return 0
