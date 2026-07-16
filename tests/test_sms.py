import pytest

from app.errors import SipError
from sip.sms import build_sms_submit_rpdata, tel_uri


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
