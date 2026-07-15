from media.rtp_packet import RtpPacket


def test_rtp_packet_roundtrip():
    packet = RtpPacket(
        payload_type=96,
        sequence=123,
        timestamp=456,
        ssrc=789,
        payload=b"payload",
        marker=True,
    )
    parsed = RtpPacket.from_bytes(packet.to_bytes())
    assert parsed.payload_type == 96
    assert parsed.sequence == 123
    assert parsed.timestamp == 456
    assert parsed.ssrc == 789
    assert parsed.payload == b"payload"
    assert parsed.marker
