"""SMS over IMS SIP MESSAGE support."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import secrets
import time

from app.config import AppConfig
from app.errors import SipError, SipReceiveTimeout
from sip.builder import SipBuilder, SipSessionIds, new_tag
from sip.dialog import extract_sip_uri
from sip.message import SipMessage
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)


@dataclass
class SmsResult:
    accepted: bool
    final_response: SipMessage


@dataclass(frozen=True)
class IncomingSmsRpData:
    message_reference: int
    originator_address: bytes
    destination_address: bytes
    tpdu: bytes


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

        # SIP transaction acknowledgement is independent of GSM RP/TP parsing.
        self.transport.send(
            self.builder.response_to_request(
                request,
                status_code=202,
                reason="Accepted",
                to_tag=new_tag(),
            )
        )
        LOGGER.info("Answered inbound SIP MESSAGE with 202 Accepted")

        content_type = (request.get("Content-Type", "") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/vnd.3gpp.sms":
            LOGGER.info("Inbound MESSAGE is not a 3GPP GSM SMS: Content-Type=%s", content_type or "<missing>")
            return True
        if not isinstance(request.body, bytes):
            LOGGER.warning("Inbound 3GPP SMS MESSAGE body is not binary; delivery report not sent")
            return True

        try:
            rp_data = parse_mt_sms_rpdata(request.body)
        except SipError as exc:
            LOGGER.warning("Invalid inbound GSM SMS RP-DATA: %s", exc)
            return True

        LOGGER.info(
            "Inbound GSM SMS RP-DATA: reference=%s originator=%s destination=%s",
            rp_data.message_reference,
            rp_data.originator_address.hex(" ").upper() or "<empty>",
            rp_data.destination_address.hex(" ").upper() or "<empty>",
        )
        LOGGER.info("Inbound GSM SMS TPDU: %s", rp_data.tpdu.hex(" ").upper())

        report_body = build_sms_delivery_report_rpack(rp_data.message_reference)
        target_uri = extract_sip_uri(request.get("From", "") or "")
        if not target_uri:
            LOGGER.warning("Inbound SMS MESSAGE has no usable From URI; delivery report not sent")
            return True

        report_ids = SipSessionIds(
            local_ip=self.local_ip,
            contact_user=ids.contact_user,
        )
        report = self.builder.message(
            report_ids,
            request_uri=target_uri,
            to_uri=target_uri,
            body=report_body,
            route_set=service_routes,
        )
        original_call_id = request.get("Call-ID", "") or ""
        if original_call_id:
            report.add_header("In-Reply-To", original_call_id)
        self.transport.send(report)
        LOGGER.info(
            "Sent GSM SMS delivery report RP-ACK: reference=%s RPDU=%s target=%s",
            rp_data.message_reference,
            report_body.hex(" ").upper(),
            target_uri,
        )
        return True

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


def parse_mt_sms_rpdata(body: bytes) -> IncomingSmsRpData:
    if len(body) < 5:
        raise SipError("RP-DATA body is too short")
    message_type = body[0] & 0x07
    if message_type != 0x01:
        raise SipError(f"Expected network-to-MS RP-DATA type 1, got {message_type}")

    message_reference = body[1]
    offset = 2
    originator_address, offset = _read_length_value(body, offset, "RP-Originator-Address")
    destination_address, offset = _read_length_value(body, offset, "RP-Destination-Address")
    tpdu, offset = _read_length_value(body, offset, "RP-User-Data")
    if offset != len(body):
        raise SipError(f"RP-DATA has {len(body) - offset} trailing bytes")
    if not tpdu:
        raise SipError("RP-DATA contains an empty TPDU")
    if (tpdu[0] & 0x03) not in (0x00, 0x02):
        raise SipError(f"Unsupported inbound GSM SMS TPDU MTI: {tpdu[0] & 0x03}")
    return IncomingSmsRpData(
        message_reference=message_reference,
        originator_address=originator_address,
        destination_address=destination_address,
        tpdu=tpdu,
    )


def build_sms_delivery_report_rpack(message_reference: int) -> bytes:
    if not 0 <= message_reference <= 255:
        raise SipError("RP message reference must fit in one octet")
    # RP-ACK direction matters: 0x02 is MS/UE -> network. The inverse
    # network -> MS flow shown by an IMS server uses 0x03.
    return bytes([0x02, message_reference])


def tel_uri(msisdn: str) -> str:
    _require_digits("msisdn", msisdn)
    return f"tel:+{msisdn}"


def _read_length_value(body: bytes, offset: int, name: str) -> tuple[bytes, int]:
    if offset >= len(body):
        raise SipError(f"RP-DATA is missing {name} length")
    length = body[offset]
    offset += 1
    end = offset + length
    if end > len(body):
        raise SipError(f"RP-DATA {name} is truncated: {length} bytes declared")
    return body[offset:end], end


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
