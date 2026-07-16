"""Parse the single-audio SDP answer used by the demo."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.errors import SipError


@dataclass(frozen=True)
class MediaPayloadFormat:
    payload_type: int
    codec: str
    fmtp: dict[str, str | bool] = field(default_factory=dict)

    @property
    def octet_aligned(self) -> bool:
        return self.fmtp.get("octet-align", "0") in ("1", "true", True)


@dataclass(frozen=True)
class RemoteMedia:
    ip: str
    port: int
    payload_type: int
    codec: str
    fmtp: dict[str, str | bool] = field(default_factory=dict)
    payload_formats: dict[int, MediaPayloadFormat] = field(default_factory=dict)
    direction: str = "sendrecv"

    @property
    def octet_aligned(self) -> bool:
        return self.fmtp.get("octet-align", "0") in ("1", "true", True)


def parse_remote_sdp(body: str) -> RemoteMedia:
    session_ip: str | None = None
    media_ip: str | None = None
    audio_port: int | None = None
    audio_payload_types: list[int] = []
    rtpmap: dict[int, str] = {}
    fmtp_by_pt: dict[int, dict[str, str | bool]] = {}
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
            audio_payload_types = [int(part) for part in parts[3:]]
        elif line.startswith("a=rtpmap:"):
            left, right = line[9:].split(None, 1)
            payload_type = int(left)
            rtpmap[payload_type] = right.split("/", 1)[0]
        elif line.startswith("a=fmtp:"):
            left, right = line[7:].split(None, 1)
            fmtp_by_pt[int(left)] = _parse_fmtp(right)
        elif line in ("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"):
            direction = line[2:]

    if audio_port is None or not audio_payload_types:
        raise SipError("Remote SDP has no audio media")
    ip = media_ip or session_ip
    if not ip:
        raise SipError("Remote SDP has no connection IP")
    payload_formats = _payload_formats(audio_payload_types, rtpmap, fmtp_by_pt)
    payload_type = _select_amrwb_payload_type(audio_payload_types, rtpmap)
    selected_format = payload_formats[payload_type]
    codec = selected_format.codec
    fmtp = selected_format.fmtp
    if codec.upper() != "AMR-WB":
        raise SipError(f"Unsupported remote codec: {codec}")

    media = RemoteMedia(
        ip=ip,
        port=audio_port,
        payload_type=payload_type,
        codec=codec,
        fmtp=fmtp,
        payload_formats=payload_formats,
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


def _select_amrwb_payload_type(payload_types: list[int], rtpmap: dict[int, str]) -> int:
    for payload_type in payload_types:
        if rtpmap.get(payload_type, "").upper() == "AMR-WB":
            return payload_type
    raise SipError(
        "Remote SDP audio media does not advertise AMR-WB in rtpmap: "
        + ", ".join(str(payload_type) for payload_type in payload_types)
    )


def _payload_formats(
    payload_types: list[int],
    rtpmap: dict[int, str],
    fmtp_by_pt: dict[int, dict[str, str | bool]],
) -> dict[int, MediaPayloadFormat]:
    return {
        payload_type: MediaPayloadFormat(
            payload_type=payload_type,
            codec=rtpmap.get(payload_type, ""),
            fmtp=fmtp_by_pt.get(payload_type, {}),
        )
        for payload_type in payload_types
    }
