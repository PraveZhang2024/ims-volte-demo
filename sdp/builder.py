"""Build minimal AMR-WB SDP offers."""

from __future__ import annotations

import time

from app.config import AppConfig


def build_amrwb_offer(
    config: AppConfig,
    local_ip: str,
    *,
    octet_align: bool | None = None,
    payload_type: int | None = None,
) -> str:
    session_id = int(time.time())
    pt = config.media.payload_type if payload_type is None else payload_type
    effective_octet_align = config.media.octet_align if octet_align is None else octet_align
    return "\r\n".join(
        [
            "v=0",
            f"o=- {session_id} {session_id} IN IP4 {local_ip}",
            "s=IMS VoLTE Demo",
            f"c=IN IP4 {local_ip}",
            "t=0 0",
            f"m=audio {config.network.local_rtp_port} RTP/AVP {pt}",
            f"a=rtpmap:{pt} AMR-WB/{config.media.clock_rate}/1",
            f"a=fmtp:{pt} octet-align={1 if effective_octet_align else 0}",
            f"a=ptime:{config.media.ptime_ms}",
            "a=maxptime:240",
            "a=sendrecv",
            "",
        ]
    )
