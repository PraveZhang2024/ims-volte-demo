"""Outgoing IMS call flow."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import socket
import time

from app.config import AppConfig
from app.errors import SipError, SipReceiveTimeout
from media.rtp_receiver import RtpReceiver
from media.rtp_sender import RtpSender
from sdp.builder import build_amrwb_offer
from sdp.parser import RemoteMedia, parse_remote_sdp
from sip.builder import SipBuilder, SipSessionIds
from sip.dialog import SipDialog, rack_from_response
from sip.message import SipMessage
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)


@dataclass
class CallResult:
    established: bool
    dialog: SipDialog
    remote_media: RemoteMedia | None = None
    final_response: SipMessage | None = None


class ImsCallClient:
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

    def establish(self, ids: SipSessionIds, service_routes: list[str]) -> CallResult:
        sdp_offer = build_amrwb_offer(self.config, self.local_ip)
        invite = self.builder.invite(ids, sdp_offer, route_set=service_routes)
        dialog = SipDialog(call_id=ids.call_id, local_tag=ids.from_tag, route_set=service_routes)

        self.transport.connect()
        self.transport.send(invite)

        remote_media: RemoteMedia | None = None
        deadline = time.monotonic() + self.config.call.setup_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError(
                    f"Timed out waiting for call setup after {self.config.call.setup_timeout_seconds} seconds"
                )
            LOGGER.info("Waiting for INVITE response, %.1f seconds remaining", remaining)
            response = self.transport.receive(timeout_seconds=remaining)
            code = response.status_code
            if code is None:
                self._handle_in_dialog_request(response)
                continue
            if 100 <= code < 200:
                LOGGER.info("Received provisional response: %s", response.start_line)
                dialog.update_from_response(response)
                if response.body:
                    remote_media = parse_remote_sdp(response.body)
                    LOGGER.info(
                        "Parsed early media SDP: remote=%s:%s PT=%s direction=%s",
                        remote_media.ip,
                        remote_media.port,
                        remote_media.payload_type,
                        remote_media.direction,
                    )
                rack = rack_from_response(response)
                if rack:
                    request_uri = dialog.request_uri(self.config.call.target_uri)
                    LOGGER.info(
                        "Sending PRACK for reliable provisional response: RAck=%s Request-URI=%s",
                        rack,
                        request_uri,
                    )
                    self.transport.send(
                        self.builder.prack(
                            ids,
                            dialog.dialog_to,
                            rack,
                            dialog.route_set,
                            request_uri=request_uri,
                        )
                    )
                continue
            if 200 <= code < 300:
                method = response.method
                if method == "PRACK":
                    continue
                if method == "INVITE":
                    dialog.update_from_response(response)
                    if response.body:
                        remote_media = parse_remote_sdp(response.body)
                        LOGGER.info(
                            "Parsed final media SDP: remote=%s:%s PT=%s direction=%s",
                            remote_media.ip,
                            remote_media.port,
                            remote_media.payload_type,
                            remote_media.direction,
                        )
                    self.transport.send(
                        self.builder.ack(
                            ids,
                            dialog.dialog_to,
                            dialog.route_set,
                            request_uri=dialog.request_uri(self.config.call.target_uri),
                        )
                    )
                    if remote_media is None:
                        raise SipError("200 INVITE has no usable remote SDP")
                    return CallResult(
                        established=True,
                        dialog=dialog,
                        remote_media=remote_media,
                        final_response=response,
                    )
            if 300 <= code < 700 and response.method == "INVITE":
                dialog.update_from_response(response)
                if dialog.dialog_to:
                    self.transport.send(self.builder.ack(ids, dialog.dialog_to, dialog.route_set))
                raise SipError(
                    f"INVITE failed with final response: {response.start_line}; "
                    f"Reason={response.get('Reason', '')}; Warning={response.get('Warning', '')}"
                )
            raise SipError(f"Unexpected SIP response during call setup: {response.start_line}")

    def run_media(self, remote_media: RemoteMedia) -> tuple[RtpSender, RtpReceiver]:
        LOGGER.info(
            "Starting media: local=%s:%s remote=%s:%s PT=%s codec=%s",
            self.local_ip,
            self.config.network.local_rtp_port,
            remote_media.ip,
            remote_media.port,
            remote_media.payload_type,
            remote_media.codec,
        )
        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock.bind((self.local_ip, self.config.network.local_rtp_port))
        sender = RtpSender.from_config(self.config, self.local_ip, remote_media, sock=rtp_sock)
        receiver = RtpReceiver.from_config(
            self.config,
            self.local_ip,
            sock=rtp_sock,
            close_socket_on_stop=True,
        )
        receiver.start()
        sender.start()
        return sender, receiver

    def bye(self, ids: SipSessionIds, dialog: SipDialog) -> SipMessage:
        self.transport.send(
            self.builder.bye(
                ids,
                dialog.dialog_to,
                dialog.route_set,
                request_uri=dialog.request_uri(self.config.call.target_uri),
            )
        )
        while True:
            response = self.transport.receive()
            if response.status_code == 200 and response.method == "BYE":
                return response
            if response.method == "BYE" and response.status_code is None:
                self._handle_in_dialog_request(response)

    def poll_during_media(self, ids: SipSessionIds, dialog: SipDialog, *, timeout_seconds: float = 0.5) -> bool:
        try:
            message = self.transport.receive(timeout_seconds=timeout_seconds)
        except SipReceiveTimeout:
            return True

        if message.status_code is not None:
            LOGGER.info("Ignoring SIP response during media: %s", message.start_line)
            return True

        method = message.method
        LOGGER.info("Received in-dialog request during media: %s", message.start_line)
        if method == "INVITE":
            sdp_offer = build_amrwb_offer(self.config, self.local_ip)
            self.transport.send(self.builder.ok_response(message, body=sdp_offer, ids=ids))
            LOGGER.info("Answered re-INVITE with 200 OK and local SDP offer")
            return True
        if method == "UPDATE":
            self.transport.send(self.builder.ok_response(message, ids=ids))
            LOGGER.info("Answered UPDATE with 200 OK")
            return True
        if method == "ACK":
            LOGGER.info("Received ACK for in-dialog transaction")
            return True
        if method == "BYE":
            self.transport.send(self.builder.ok_response(message))
            LOGGER.info("Remote side ended the call with BYE")
            return False

        LOGGER.info("Ignoring unsupported in-dialog request: %s", message.start_line)
        return True

    def close(self) -> None:
        self.transport.close()

    def _handle_in_dialog_request(self, request: SipMessage) -> None:
        if request.method == "BYE":
            self.transport.send(self.builder.ok_response(request))
            raise SipError("Remote side ended the call with BYE")
        LOGGER.info("Ignoring in-dialog request for first demo version: %s", request.start_line)
