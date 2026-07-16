"""SMS over IMS SIP MESSAGE support."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import secrets
import time

from app.config import AppConfig
from app.errors import SipError, SipReceiveTimeout
from sip.builder import SipBuilder, SipSessionIds
from sip.message import SipMessage
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)


@dataclass
class SmsResult:
    accepted: bool
    final_response: SipMessage


class ImsSmsClient:
    def __init__(
        self,
        config: AppConfig,
        local_ip: str,
        transport: SipTcpTransport | None = None,
    ) -> None:
        self.config = config
        self.local_ip = local_ip
        self.builder = SipBuilder(config, local_ip, protected=True)
        self.transport = transport or SipTcpTransport(
            local_ip=local_ip,
            local_port=config.network.local_protected_port,
            remote_ip=config.network.pcscf_ip,
            remote_port=config.network.pcscf_port,
            timeout_seconds=config.network.connect_timeout_seconds,
            dump_sip=config.debug.dump_sip,
        )

    def send_sms(
        self,
        ids: SipSessionIds,
        *,
        smsc: str,
        target_msisdn: str,
        content: str,
        service_routes: list[str],
    ) -> SmsResult:
        body = build_sms_submit_rpdata(
            smsc=smsc,
            target_msisdn=target_msisdn,
            content=content,
        )
        message = self.builder.message(
            ids,
            request_uri=tel_uri(smsc),
            to_uri=tel_uri(smsc),
            body=body,
            route_set=service_routes,
        )
        self.transport.connect()
        self.transport.send(message)

        deadline = time.monotonic() + self.config.call.setup_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError(
                    f"Timed out waiting for SMS MESSAGE response after {self.config.call.setup_timeout_seconds} seconds"
                )
            try:
                response = self.transport.receive(timeout_seconds=remaining)
            except SipReceiveTimeout as exc:
                raise SipError("Timed out waiting for SMS MESSAGE response") from exc

            if response.status_code is None:
                LOGGER.info("Ignoring SIP request while waiting for SMS response: %s", response.start_line)
                continue
            if response.method != "MESSAGE":
                LOGGER.info("Ignoring SIP response for another method while waiting for SMS: %s", response.start_line)
                continue
            if 100 <= response.status_code < 200:
                LOGGER.info("Received provisional SMS MESSAGE response: %s", response.start_line)
                continue
            if 200 <= response.status_code < 300:
                LOGGER.info("SMS MESSAGE accepted: %s", response.start_line)
                return SmsResult(accepted=True, final_response=response)
            raise SipError(f"SMS MESSAGE failed: {response.start_line}")

    def close(self) -> None:
        self.transport.close()


def build_sms_submit_rpdata(*, smsc: str, target_msisdn: str, content: str) -> bytes:
    """Build RP-DATA carrying an SMS-SUBMIT TPDU with UCS-2 user data."""
    _require_digits("smsc", smsc)
    _require_digits("target_msisdn", target_msisdn)
    user_data = _ucs2_user_data(content)

    tpdu = bytearray()
    tpdu.append(0x01)  # SMS-SUBMIT, no validity period.
    tpdu.append(secrets.randbelow(256))
    tpdu.extend(_tp_address(target_msisdn))
    tpdu.append(0x00)  # TP-PID
    tpdu.append(0x08)  # TP-DCS: UCS-2
    tpdu.append(len(user_data))
    tpdu.extend(user_data)

    if len(tpdu) > 255:
        raise SipError("SMS TPDU is too long for RP-User-Data")

    rpdu = bytearray()
    rpdu.append(0x00)  # RP-DATA, MS to network.
    rpdu.append(secrets.randbelow(256))
    rpdu.append(0x00)  # RP-Originator-Address length.
    rp_destination = _rp_address(smsc)
    rpdu.append(len(rp_destination))
    rpdu.extend(rp_destination)
    rpdu.append(len(tpdu))
    rpdu.extend(tpdu)
    return bytes(rpdu)


def tel_uri(msisdn: str) -> str:
    _require_digits("msisdn", msisdn)
    return f"tel:+{msisdn}"


def _tp_address(msisdn: str) -> bytes:
    return bytes([len(msisdn), 0x91]) + _semi_octets(msisdn)


def _rp_address(msisdn: str) -> bytes:
    return bytes([0x91]) + _semi_octets(msisdn)


def _semi_octets(digits: str) -> bytes:
    padded = digits if len(digits) % 2 == 0 else digits + "f"
    encoded = bytearray()
    for index in range(0, len(padded), 2):
        encoded.append(int(padded[index + 1] + padded[index], 16))
    return bytes(encoded)


def _require_digits(name: str, value: str) -> None:
    if not value or not value.isascii() or not value.isdigit():
        raise SipError(f"{name} must contain digits only")


def _ucs2_user_data(content: str) -> bytes:
    if any(ord(char) > 0xFFFF for char in content):
        raise SipError("SMS content contains characters outside UCS-2")
    user_data = content.encode("utf-16-be")
    if len(user_data) > 140:
        raise SipError("UCS-2 SMS content is too long for one SMS TPDU")
    return user_data
