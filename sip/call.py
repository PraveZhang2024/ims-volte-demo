"""Outgoing IMS call flow."""

from __future__ import annotations

from dataclasses import dataclass
import logging

from app.config import AppConfig
from app.errors import SipError
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
    def __init__(self, config: AppConfig, local_ip: str) -> None:
        self.config = config
        self.local_ip = local_ip
        self.builder = SipBuilder(config, local_ip, protected=True)
        self.transport = SipTcpTransport(
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
        while True:
            response = self.transport.receive()
            code = response.status_code
            if code is None:
                self._handle_in_dialog_request(response)
                continue
            if code in (100, 180):
                LOGGER.info("Received provisional response: %s", response.start_line)
                dialog.update_from_response(response)
                continue
            if code == 183:
                dialog.update_from_response(response)
                if response.body:
                    remote_media = parse_remote_sdp(response.body)
                rack = rack_from_response(response)
                if rack:
                    self.transport.send(self.builder.prack(ids, dialog.dialog_to, rack, dialog.route_set))
                continue
            if 200 <= code < 300:
                method = response.method
                if method == "PRACK":
                    continue
                if method == "INVITE":
                    dialog.update_from_response(response)
                    if response.body:
                        remote_media = parse_remote_sdp(response.body)
                    self.transport.send(self.builder.ack(ids, dialog.dialog_to, dialog.route_set))
                    if remote_media is None:
                        raise SipError("200 INVITE has no usable remote SDP")
                    return CallResult(
                        established=True,
                        dialog=dialog,
                        remote_media=remote_media,
                        final_response=response,
                    )
            raise SipError(f"Unexpected SIP response during call setup: {response.start_line}")

    def run_media(self, remote_media: RemoteMedia) -> tuple[RtpSender, RtpReceiver]:
        sender = RtpSender.from_config(self.config, self.local_ip, remote_media)
        receiver = RtpReceiver.from_config(self.config, self.local_ip)
        receiver.start()
        sender.start()
        return sender, receiver

    def bye(self, ids: SipSessionIds, dialog: SipDialog) -> SipMessage:
        self.transport.send(self.builder.bye(ids, dialog.dialog_to, dialog.route_set))
        while True:
            response = self.transport.receive()
            if response.status_code == 200 and response.method == "BYE":
                return response
            if response.method == "BYE" and response.status_code is None:
                self._handle_in_dialog_request(response)

    def close(self) -> None:
        self.transport.close()

    def _handle_in_dialog_request(self, request: SipMessage) -> None:
        if request.method == "BYE":
            self.transport.send(self.builder.ok_response(request))
            raise SipError("Remote side ended the call with BYE")
        LOGGER.info("Ignoring in-dialog request for first demo version: %s", request.start_line)
