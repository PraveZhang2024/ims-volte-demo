from sdp.parser import parse_remote_sdp


def test_parse_remote_amrwb_sdp():
    media = parse_remote_sdp(
        "\r\n".join(
            [
                "v=0",
                "o=- 1 1 IN IP4 10.0.0.2",
                "s=-",
                "c=IN IP4 10.0.0.2",
                "t=0 0",
                "m=audio 50000 RTP/AVP 96",
                "a=rtpmap:96 AMR-WB/16000/1",
                "a=fmtp:96 octet-align=1",
                "a=sendrecv",
                "",
            ]
        )
    )
    assert media.ip == "10.0.0.2"
    assert media.port == 50000
    assert media.payload_type == 96
    assert media.octet_aligned


def test_parse_remote_amrwb_sdp_accepts_bandwidth_efficient_mode():
    media = parse_remote_sdp(
        "\r\n".join(
            [
                "v=0",
                "o=- 1 1 IN IP4 10.0.0.2",
                "s=-",
                "c=IN IP4 10.0.0.2",
                "t=0 0",
                "m=audio 50000 RTP/AVP 96",
                "a=rtpmap:96 AMR-WB/16000/1",
                "a=fmtp:96 octet-align=0",
                "a=sendrecv",
                "",
            ]
        )
    )
    assert not media.octet_aligned


def test_parse_remote_amrwb_sdp_selects_rtpmap_payload_not_first_m_line_payload():
    media = parse_remote_sdp(
        "\r\n".join(
            [
                "v=0",
                "o=- 1 1 IN IP4 10.0.0.2",
                "s=-",
                "c=IN IP4 10.0.0.2",
                "t=0 0",
                "m=audio 50000 RTP/AVP 96 98",
                "a=rtpmap:96 telephone-event/16000",
                "a=rtpmap:98 AMR-WB/16000/1",
                "a=fmtp:98 octet-align=0",
                "a=sendrecv",
                "",
            ]
        )
    )
    assert media.payload_type == 98
    assert media.codec == "AMR-WB"
    assert not media.octet_aligned
