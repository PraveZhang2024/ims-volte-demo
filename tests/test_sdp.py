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
