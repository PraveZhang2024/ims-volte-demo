from aka.digest_akav1 import DigestCredentials, build_authorization, calculate_response, digest_debug
from aka.milenage_service import AkaResult
from app.config import AppConfig, CallConfig, DebugConfig, ImsConfig, MediaConfig, NetworkConfig, SubscriberConfig
from sip.register import ImsRegistrationClient


def test_digest_authorization_contains_expected_fields():
    credentials = DigestCredentials(
        username="001@ims",
        realm="ims",
        uri="sip:ims",
        method="REGISTER",
        password="01020304",
        nonce="nonce",
        qop="auth",
        opaque="opaque",
        cnonce="cnonce",
    )
    header = build_authorization(credentials)
    assert header.startswith("Digest ")
    assert 'username="001@ims"' in header
    assert "algorithm=AKAv1-MD5" in header
    assert f'response="{calculate_response(credentials)}"' in header


def test_digest_can_use_raw_res_bytes_as_password():
    raw = DigestCredentials(
        username="001@ims",
        realm="ims",
        uri="sip:ims",
        method="REGISTER",
        password=b"\x01\x02\x03\x04",
        nonce="nonce",
    )
    text = DigestCredentials(
        username="001@ims",
        realm="ims",
        uri="sip:ims",
        method="REGISTER",
        password="01020304",
        nonce="nonce",
    )
    assert calculate_response(raw) != calculate_response(text)


def test_digest_debug_exposes_inputs_and_matches_authorization_response():
    credentials = DigestCredentials(
        username="001@ims",
        realm="ims",
        uri="sip:ims",
        method="REGISTER",
        password="01020304",
        nonce="nonce",
        qop="auth",
        cnonce="fixed",
    )
    debug = digest_debug(credentials)
    header = build_authorization(credentials)
    assert debug.ha1_input_debug == "001@ims:ims:01020304"
    assert debug.ha2_input == "REGISTER:sip:ims"
    assert f'response="{debug.response}"' in header


def test_register_authorization_uri_matches_register_request_uri_when_challenge_realm_differs():
    config = AppConfig(
        network=NetworkConfig(
            interface="ims0",
            pcscf_ip="10.0.0.2",
            pcscf_port=5060,
            local_sip_port=5060,
            local_protected_port=15060,
            local_rtp_port=40000,
        ),
        subscriber=SubscriberConfig(
            imsi="00101",
            impi="00101@ims.mnc009.mcc404.3gppnetwork.org",
            impu="sip:+100@ims.mnc009.mcc404.3gppnetwork.org",
            realm="ims.mnc009.mcc404.3gppnetwork.org",
            k="00" * 16,
            opc="11" * 16,
        ),
        call=CallConfig(target_uri="sip:+101@ims.mnc009.mcc404.3gppnetwork.org", duration_seconds=1, local_display_name="UE"),
        ims=ImsConfig(),
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
        base_dir=__import__("pathlib").Path("."),
    )
    client = ImsRegistrationClient(config=config, local_ip="190.0.0.38", xfrm_manager=None)  # type: ignore[arg-type]
    header = client._authorization(
        {"realm": "ims.system.com", "nonce": "nonce", "algorithm": "AKAv1-MD5"},
        AkaResult(res=b"\x01\x02", ck=b"\x00" * 16, ik=b"\x11" * 16, ak=b"", sqn=b"", mac_verified=True),
    )
    assert 'realm="ims.system.com"' in header
    assert 'uri="sip:ims.mnc009.mcc404.3gppnetwork.org"' in header
