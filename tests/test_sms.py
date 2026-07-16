import pytest

from app.errors import SipError
from sip.sms import build_sms_delivery_report_rpack, build_sms_submit_rpdata, parse_sms_deliver_rpdata, tel_uri


def test_build_sms_submit_rpdata_encodes_smsc_target_and_ucs2(monkeypatch):
    refs = iter([0x18, 0x1A])
    monkeypatch.setattr("sip.sms.secrets.randbelow", lambda _limit: next(refs))

    body = build_sms_submit_rpdata(
        smsc="8613900139000",
        target_msisdn="8616510000896",
        content="中",
    )

    assert body == bytes.fromhex(
        "00 1a 00 08 91 68 31 09 10 93 00 f0 "
        "10 01 18 0d 91 68 61 15 00 00 98 f6 00 08 02 4e 2d"
    )


def test_sms_rejects_non_digit_numbers():
    with pytest.raises(SipError):
        tel_uri("+8613900139000")


def test_parse_sms_deliver_rpdata_decodes_ucs2_message():
    body = bytes.fromhex(
        "01 02 08 91 68 31 09 10 93 00 f0 00 1b 24 0b a1 "
        "61 15 00 00 98 f6 00 08 62 70 61 81 51 34 23 08 "
        "51 e1 6b 64 79 cd 79 cd"
    )

    sms = parse_sms_deliver_rpdata(body)

    assert sms.rp_message_reference == 0x02
    assert sms.originator == "16510000896"
    assert sms.dcs == 0x08
    assert sms.service_center_timestamp == "2026-07-16 18:15:43 TZ=32"
    assert sms.content == "凡此种种"


def test_build_sms_delivery_report_rpack_uses_inbound_reference():
    assert build_sms_delivery_report_rpack(0x02) == bytes.fromhex("04 02 41 01 00")
