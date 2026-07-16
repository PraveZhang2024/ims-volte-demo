from media.amrwb_payload import AmrWbFrame, frame_to_rtp_payload, rtp_payload_to_frame


def test_amrwb_frame_rtp_payload_roundtrip():
    frame = AmrWbFrame(ft=0, quality=True, speech=bytes(range(17)))
    payload = frame_to_rtp_payload(frame)
    parsed = rtp_payload_to_frame(payload)
    assert parsed == frame


def test_amrwb_bandwidth_efficient_payload_roundtrip():
    frame = AmrWbFrame(ft=0, quality=True, speech=bytes(range(17)))
    payload = frame_to_rtp_payload(frame, octet_aligned=False)
    parsed = rtp_payload_to_frame(payload, octet_aligned=False)
    assert parsed == frame
    assert len(payload) < len(frame_to_rtp_payload(frame, octet_aligned=True))
