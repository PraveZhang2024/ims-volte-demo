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


@dataclass
class InboundSms:
    rp_message_reference: int
    originator: str
    pid: int
    dcs: int
    service_center_timestamp: str
    content: str
    raw_body: bytes


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

    def handle_inbound_message(
        self,
        ids: SipSessionIds,
        request: SipMessage,
        *,
        service_routes: list[str],
    ) -> bool:
        if request.method != "MESSAGE":
            return False

        self.transport.send(self.builder.ok_response(request))
        if not is_sms_message(request):
            LOGGER.info("Received non-SMS SIP MESSAGE: %s", request.start_line)
            return True

        try:
            inbound = parse_sms_deliver_rpdata(_sms_body_bytes(request))
        except SipError as exc:
            LOGGER.warning("Received SMS SIP MESSAGE but could not parse GSM SMS body: %s", exc)
            return True
        LOGGER.info(
            "Received SMS from %s at %s: %s",
            inbound.originator or "<unknown>",
            inbound.service_center_timestamp or "<unknown time>",
            inbound.content,
        )
        print(f"SMS from {inbound.originator or '<unknown>'}: {inbound.content}")

        report = self.builder.message(
            ids,
            request_uri=_message_reply_uri(request),
            to_uri=_message_reply_uri(request),
            body=build_sms_delivery_report_rpack(inbound.rp_message_reference),
            route_set=service_routes,
        )
        self.transport.send(report)
        self._wait_for_message_ok()
        return True

    def _wait_for_message_ok(self) -> SipMessage:
        deadline = time.monotonic() + self.config.call.setup_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError("Timed out waiting for SMS delivery report response")
            try:
                response = self.transport.receive(timeout_seconds=remaining)
            except SipReceiveTimeout as exc:
                raise SipError("Timed out waiting for SMS delivery report response") from exc

            if response.status_code is None:
                LOGGER.info("Ignoring SIP request while waiting for SMS delivery report response: %s", response.start_line)
                continue
            if response.method != "MESSAGE":
                LOGGER.info("Ignoring SIP response for another method while waiting for delivery report: %s", response.start_line)
                continue
            if 100 <= response.status_code < 200:
                LOGGER.info("Received provisional SMS delivery report response: %s", response.start_line)
                continue
            if 200 <= response.status_code < 300:
                LOGGER.info("SMS delivery report accepted: %s", response.start_line)
                return response
            raise SipError(f"SMS delivery report failed: {response.start_line}")

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


def parse_sms_deliver_rpdata(body: bytes) -> InboundSms:
    """Parse RP-DATA carrying an SMS-DELIVER TPDU."""
    if len(body) < 5:
        raise SipError("SMS RP-DATA body is too short")
    if body[0] != 0x01:
        raise SipError(f"Unsupported SMS RP message type: 0x{body[0]:02x}")

    rp_message_reference = body[1]
    offset = 2
    _originator, offset = _read_rp_address(body, offset)
    _destination, offset = _read_rp_address(body, offset)
    if offset >= len(body):
        raise SipError("SMS RP-DATA is missing RP-User-Data")

    tpdu_length = body[offset]
    offset += 1
    tpdu = body[offset : offset + tpdu_length]
    if len(tpdu) != tpdu_length:
        raise SipError("SMS RP-DATA has truncated TPDU")

    originator, pid, dcs, timestamp, content = _parse_sms_deliver_tpdu(tpdu)
    return InboundSms(
        rp_message_reference=rp_message_reference,
        originator=originator,
        pid=pid,
        dcs=dcs,
        service_center_timestamp=timestamp,
        content=content,
        raw_body=body,
    )


def build_sms_delivery_report_rpack(rp_message_reference: int) -> bytes:
    if not 0 <= rp_message_reference <= 0xFF:
        raise SipError("RP message reference must fit in one octet")
    return bytes([0x04, rp_message_reference, 0x41, 0x01, 0x00])


def is_sms_message(message: SipMessage) -> bool:
    content_type = message.get("Content-Type", "") or ""
    return content_type.split(";", 1)[0].strip().lower() == "application/vnd.3gpp.sms"


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


def _sms_body_bytes(message: SipMessage) -> bytes:
    if isinstance(message.body, bytes):
        return message.body
    return message.body.encode("latin1")


def _read_rp_address(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        raise SipError("SMS RP address is truncated")
    length = data[offset]
    offset += 1
    address = data[offset : offset + length]
    if len(address) != length:
        raise SipError("SMS RP address length exceeds body")
    if not address:
        return "", offset + length
    return _decode_address(address[0], address[1:]), offset + length


def _parse_sms_deliver_tpdu(tpdu: bytes) -> tuple[str, int, int, str, str]:
    if len(tpdu) < 12:
        raise SipError("SMS-DELIVER TPDU is too short")
    first_octet = tpdu[0]
    if first_octet & 0x03:
        raise SipError(f"Unsupported SMS TPDU type for inbound SMS: 0x{first_octet:02x}")

    offset = 1
    originator_digits = tpdu[offset]
    offset += 1
    if offset >= len(tpdu):
        raise SipError("SMS-DELIVER originator address is truncated")
    originator_type = tpdu[offset]
    offset += 1
    originator_length = (originator_digits + 1) // 2
    originator = _decode_address(
        originator_type,
        tpdu[offset : offset + originator_length],
        digit_count=originator_digits,
    )
    offset += originator_length
    if offset + 10 > len(tpdu):
        raise SipError("SMS-DELIVER TPDU is missing PID/DCS/SCTS/UDL")

    pid = tpdu[offset]
    dcs = tpdu[offset + 1]
    timestamp = _decode_timestamp(tpdu[offset + 2 : offset + 9])
    user_data_length = tpdu[offset + 9]
    user_data = tpdu[offset + 10 :]
    has_user_data_header = bool(first_octet & 0x40)
    content = _decode_user_data(dcs, user_data_length, user_data, has_user_data_header)
    return originator, pid, dcs, timestamp, content


def _decode_address(type_of_address: int, encoded: bytes, *, digit_count: int | None = None) -> str:
    digits = _decode_semi_octets(encoded, digit_count=digit_count)
    if ((type_of_address >> 4) & 0x07) == 0x01 and digits:
        return f"+{digits}"
    return digits


def _decode_semi_octets(encoded: bytes, *, digit_count: int | None = None) -> str:
    chars: list[str] = []
    for value in encoded:
        chars.append(f"{value & 0x0F:x}")
        chars.append(f"{(value >> 4) & 0x0F:x}")
    digits = "".join(chars).rstrip("f")
    return digits[:digit_count] if digit_count is not None else digits


def _decode_timestamp(encoded: bytes) -> str:
    if len(encoded) != 7:
        return ""
    parts = [_decode_semi_octets(bytes([value]), digit_count=2) for value in encoded]
    return f"20{parts[0]}-{parts[1]}-{parts[2]} {parts[3]}:{parts[4]}:{parts[5]} TZ={parts[6]}"


def _decode_user_data(dcs: int, user_data_length: int, user_data: bytes, has_user_data_header: bool) -> str:
    if (dcs & 0x0C) == 0x08:
        payload = user_data[:user_data_length]
        if has_user_data_header and payload:
            header_length = payload[0] + 1
            payload = payload[header_length:]
        return payload.decode("utf-16-be", errors="replace")
    if (dcs & 0x0C) == 0x04:
        payload = user_data[:user_data_length]
        if has_user_data_header and payload:
            header_length = payload[0] + 1
            payload = payload[header_length:]
        return payload.hex(" ")
    return _decode_gsm_7bit(user_data, user_data_length, has_user_data_header=has_user_data_header)


GSM_7BIT_DEFAULT_ALPHABET = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ"
    "\x1bÆæßÉ !\"#¤%&'()*+,-./"
    "0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmnopqrstuvwxyzäöñüà"
)


def _decode_gsm_7bit(data: bytes, septet_count: int, *, has_user_data_header: bool) -> str:
    chars: list[str] = []
    carry_bits = 0
    carry = 0
    for value in data:
        septet = ((value << carry_bits) & 0x7F) | carry
        chars.append(GSM_7BIT_DEFAULT_ALPHABET[septet])
        carry = value >> (7 - carry_bits)
        carry_bits += 1
        if carry_bits == 7:
            chars.append(GSM_7BIT_DEFAULT_ALPHABET[carry & 0x7F])
            carry = 0
            carry_bits = 0
        if len(chars) >= septet_count:
            break
    text = "".join(chars[:septet_count])
    if has_user_data_header and data:
        header_octets = data[0] + 1
        header_septets = (header_octets * 8 + 6) // 7
        return text[header_septets:]
    return text


def _message_reply_uri(request: SipMessage) -> str:
    from_value = request.get("From", "") or ""
    uri = _extract_uri(from_value)
    if uri:
        return uri
    return request.start_line.split(maxsplit=2)[1]


def _extract_uri(value: str) -> str:
    value = value.strip()
    if "<" in value and ">" in value:
        return value.split("<", 1)[1].split(">", 1)[0].strip()
    return value.split(";", 1)[0].strip()
