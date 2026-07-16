"""Parse the single-audio SDP answer used by the demo."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.errors import SipError


@dataclass(frozen=True)
class RemoteMedia:
    ip: str
    port: int
    payload_type: int
    codec: str
    fmtp: dict[str, str | bool] = field(default_factory=dict)
    direction: str = "sendrecv"

    @property
    def octet_aligned(self) -> bool:
        return self.fmtp.get("octet-align", "0") in ("1", "true", True)


def parse_remote_sdp(body: str) -> RemoteMedia:
    session_ip: str | None = None
    media_ip: str | None = None
    audio_port: int | None = None
    payload_type: int | None = None
    codec = ""
    fmtp: dict[str, str | bool] = {}
    direction = "sendrecv"

    for raw_line in body.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("c=IN IP4 "):
            ip = line.split()[-1]
            if audio_port is None:
                session_ip = ip
            else:
                media_ip = ip
        elif line.startswith("m=audio "):
            parts = line.split()
            if len(parts) < 4:
                raise SipError(f"Invalid audio media line: {line}")
            audio_port = int(parts[1])
            payload_type = int(parts[3])
        elif line.startswith("a=rtpmap:"):
            left, right = line[9:].split(None, 1)
            if payload_type is None or int(left) == payload_type:
                codec = right.split("/", 1)[0]
        elif line.startswith("a=fmtp:"):
            left, right = line[7:].split(None, 1)
            if payload_type is None or int(left) == payload_type:
                fmtp.update(_parse_fmtp(right))
        elif line in ("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"):
            direction = line[2:]

    if audio_port is None or payload_type is None:
        raise SipError("Remote SDP has no audio media")
    ip = media_ip or session_ip
    if not ip:
        raise SipError("Remote SDP has no connection IP")
    if codec.upper() != "AMR-WB":
        raise SipError(f"Unsupported remote codec: {codec}")

    media = RemoteMedia(
        ip=ip,
        port=audio_port,
        payload_type=payload_type,
        codec=codec,
        fmtp=fmtp,
        direction=direction,
    )
    return media


def _parse_fmtp(value: str) -> dict[str, str | bool]:
    params: dict[str, str | bool] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            params[key.strip()] = val.strip()
        else:
            params[part] = True
    return params
