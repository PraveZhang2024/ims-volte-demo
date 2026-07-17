import pytest

from app.errors import SipError
from sip.sms import (
    build_sms_delivery_report_rpack,
    build_sms_submit_rpdata,
    parse_mt_sms_rpdata,
    tel_uri,
)


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


def test_parse_mt_sms_rpdata_extracts_tpdu_and_reference():
    body = bytes.fromhex("01 7a 02 91 21 00 03 00 aa bb")
    parsed = parse_mt_sms_rpdata(body)
    assert parsed.message_reference == 0x7A
    assert parsed.originator_address == bytes.fromhex("91 21")
    assert parsed.destination_address == b""
    assert parsed.tpdu == bytes.fromhex("00 aa bb")


def test_build_sms_delivery_report_rpack_is_two_byte_ue_to_network_rpack():
    assert build_sms_delivery_report_rpack(0x7A) == bytes.fromhex("02 7a")
