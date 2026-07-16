"""SIP MESSAGE flow for sending a small SMS-over-SIP text payload."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import time

from app.config import AppConfig
from app.errors import SipError
from sip.builder import SipBuilder, SipSessionIds
from sip.message import SipMessage
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)

DEFAULT_SMS_TEXT = "你好"
UCS2_TEXT_CONTENT_TYPE = "text/plain;charset=UTF-16BE"


@dataclass
class SmsResult:
    accepted: bool
    response: SipMessage


def ucs2_text_body(text: str = DEFAULT_SMS_TEXT) -> bytes:
    return text.encode("utf-16-be")


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

    def send_text_message(
        self,
        ids: SipSessionIds,
        route_set: list[str],
        *,
        target_uri: str,
        text: str = DEFAULT_SMS_TEXT,
    ) -> SmsResult:
        if not target_uri:
            raise SipError("target_uri is required for SIP MESSAGE")

        body = ucs2_text_body(text)
        message = self.builder.message(
            ids,
            body,
            target=target_uri,
            route_set=route_set,
            content_type=UCS2_TEXT_CONTENT_TYPE,
        )

        self.transport.connect()
        self.transport.send(message)
        LOGGER.info("Sent SIP MESSAGE to %s with UCS-2 text payload: %s", target_uri, text)

        deadline = time.monotonic() + self.config.network.connect_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError("Timed out waiting for SIP MESSAGE response")

            response = self.transport.receive(timeout_seconds=remaining)
            code = response.status_code
            if code is None:
                LOGGER.info("Ignoring request while waiting for MESSAGE response: %s", response.start_line)
                continue
            if response.method != "MESSAGE":
                LOGGER.info("Ignoring response for %s while waiting for MESSAGE", response.method)
                continue
            if 100 <= code < 200:
                LOGGER.info("Received provisional MESSAGE response: %s", response.start_line)
                continue
            if 200 <= code < 300:
                LOGGER.info("SIP MESSAGE accepted: %s", response.start_line)
                return SmsResult(accepted=True, response=response)
            raise SipError(
                f"SIP MESSAGE failed with final response: {response.start_line}; "
                f"Reason={response.get('Reason', '')}; Warning={response.get('Warning', '')}"
            )

    def close(self) -> None:
        self.transport.close()
