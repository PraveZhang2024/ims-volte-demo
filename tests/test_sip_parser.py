from sip.parser import SipStreamParser, parse_sip_message


def test_parse_sip_response_headers_and_body():
    raw = (
        "SIP/2.0 401 Unauthorized\r\n"
        "Via: SIP/2.0/TCP 1.2.3.4:5060\r\n"
        "WWW-Authenticate: Digest realm=\"ims\", nonce=\"abc\", algorithm=AKAv1-MD5\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "body"
    )
    msg = parse_sip_message(raw)
    assert msg.status_code == 401
    assert msg.get("www-authenticate") is not None
    assert msg.body == "body"


def test_stream_parser_handles_split_and_coalesced_messages():
    one = b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n"
    two = b"SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"
    parser = SipStreamParser()
    assert parser.feed(one[:10]) == []
    messages = parser.feed(one[10:] + two)
    assert [msg.status_code for msg in messages] == [100, 180]


def test_parse_binary_sms_body_keeps_bytes():
    raw = (
        b"MESSAGE sip:user@example.test SIP/2.0\r\n"
        b"Content-Type: application/vnd.3gpp.sms\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"\x01\x02"
    )

    msg = parse_sip_message(raw)

    assert msg.method == "MESSAGE"
    assert msg.body == b"\x01\x02"
