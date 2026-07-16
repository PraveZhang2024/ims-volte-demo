from pathlib import Path

from app.config import AppConfig, CallConfig, DebugConfig, ImsConfig, MediaConfig, NetworkConfig, SubscriberConfig
from sip.builder import SipBuilder, SipSessionIds
from sip.sms import UCS2_TEXT_CONTENT_TYPE, ucs2_text_body


def _test_config() -> AppConfig:
    return AppConfig(
        network=NetworkConfig(
            interface="ims0",
            pcscf_ip="10.0.0.2",
            pcscf_port=5060,
            local_sip_port=25060,
            local_protected_port=25061,
            local_rtp_port=24000,
        ),
        subscriber=SubscriberConfig(
            imsi="00101",
            impi="00101@ims.example",
            impu="sip:+100@ims.example",
            realm="ims.example",
            k="00" * 16,
            opc="11" * 16,
        ),
        call=CallConfig(target_uri="sip:+101@ims.example", local_display_name="UE"),
        ims=ImsConfig(contact_transport="tcp"),
        media=MediaConfig(
            codec="AMR-WB",
            payload_type=96,
            clock_rate=16000,
            ptime_ms=20,
            octet_align=True,
            send_file="send.amr",
            receive_file="received.amr",
        ),
        debug=DebugConfig(
            dump_sip=True,
            dump_sdp=True,
            dump_xfrm_commands=True,
            execute_xfrm_commands=False,
            capture_pcap=False,
        ),
        base_dir=Path("."),
    )


def test_contact_uri_advertises_tcp_transport_inside_uri():
    config = _test_config()
    ids = SipSessionIds(local_ip="190.0.0.44")
    msg = SipBuilder(config, "190.0.0.44", protected=True).invite(ids, "v=0\r\n")
    assert ";transport=tcp>" in (msg.get("Contact") or "")


def test_message_uses_ucs2_body_length():
    config = _test_config()
    ids = SipSessionIds(local_ip="190.0.0.44")
    body = ucs2_text_body()
    msg = SipBuilder(config, "190.0.0.44", protected=True).message(ids, body)
    raw = msg.to_bytes()

    assert msg.get("Content-Type") == UCS2_TEXT_CONTENT_TYPE
    assert b"\r\nl: 4\r\n" in raw
    assert raw.endswith("你好".encode("utf-16-be"))
