"""Outgoing IMS call flow."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import random
import socket
import time
from typing import Callable

from app.config import AppConfig
from app.errors import SipError, SipReceiveTimeout
from media.rtp_receiver import RtpReceiver
from media.rtp_sender import RtpSender
from sdp.builder import build_amrwb_offer
from sdp.parser import RemoteMedia, parse_remote_sdp
from sip.builder import SipBuilder, SipSessionIds, new_tag
from sip.dialog import SipDialog, rack_from_response
from sip.message import SipMessage
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)


@dataclass
class CallResult:
    established: bool
    dialog: SipDialog
    ids: SipSessionIds
    remote_media: RemoteMedia | None = None
    final_response: SipMessage | None = None


class IncomingCallCancelled(Exception):
    """Raised internally when an inbound INVITE is cancelled before answer."""


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
        self._awaiting_reinvite_answer = False
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
                        ids=ids,
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

    def wait_for_incoming_call(
        self,
        registration_ids: SipSessionIds,
        *,
        request_handler: Callable[[SipMessage], bool] | None = None,
    ) -> CallResult:
        LOGGER.info("Waiting for incoming INVITE")
        while True:
            try:
                request = self.transport.receive(timeout_seconds=1.0)
            except SipReceiveTimeout:
                continue
            if request.status_code is not None:
                LOGGER.info("Ignoring SIP response while listening: %s", request.start_line)
                continue
            if request.method == "ACK":
                LOGGER.info("Received ACK for a completed/cancelled inbound INVITE while listening")
                continue
            if request.method != "INVITE":
                if request_handler and request_handler(request):
                    continue
                LOGGER.info("Ignoring non-INVITE request while listening: %s", request.start_line)
                continue

            if not request.body:
                raise SipError("Incoming INVITE has no SDP offer")
            remote_media = parse_remote_sdp(request.body)
            local_tag = new_tag()
            ids = SipSessionIds(
                local_ip=self.local_ip,
                call_id=request.get("Call-ID", "") or "",
                from_tag=local_tag,
                contact_user=registration_ids.contact_user,
            )
            dialog = SipDialog.from_incoming_invite(request, local_tag=local_tag)

            self.transport.send(
                self.builder.response_to_request(
                    request,
                    status_code=180,
                    reason="Ringing",
                    ids=ids,
                    to_tag=local_tag,
                )
            )
            delay = random.uniform(3, 10)
            LOGGER.info("Incoming call received; answering after %.1f seconds", delay)
            try:
                self._wait_before_answer(delay, request, local_tag)
            except IncomingCallCancelled:
                LOGGER.info("Incoming call was cancelled before answer; returning to listen state")
                continue

            sdp_answer = build_amrwb_offer(
                self.config,
                self.local_ip,
                octet_align=remote_media.octet_aligned,
                payload_type=remote_media.payload_type,
            )
            self.transport.send(
                self.builder.ok_response(
                    request,
                    body=sdp_answer,
                    ids=ids,
                    to_tag=local_tag,
                )
            )
            LOGGER.info("Sent 200 OK for incoming INVITE; waiting for ACK")

            try:
                self._wait_for_ack(dialog, request, local_tag)
            except IncomingCallCancelled:
                LOGGER.info("Incoming call was cancelled while waiting for ACK; returning to listen state")
                continue
            LOGGER.info("Incoming call established")
            return CallResult(
                established=True,
                dialog=dialog,
                ids=ids,
                remote_media=remote_media,
                final_response=None,
            )

    def _wait_before_answer(self, delay_seconds: float, invite: SipMessage, local_tag: str) -> None:
        deadline = time.monotonic() + delay_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                message = self.transport.receive(timeout_seconds=min(0.2, remaining))
            except SipReceiveTimeout:
                continue
            if message.status_code is not None:
                LOGGER.info("Ignoring SIP response before answering inbound call: %s", message.start_line)
                continue
            if message.method == "CANCEL":
                self._answer_cancel(message, invite, local_tag)
                raise IncomingCallCancelled()
            LOGGER.info("Ignoring request before answering inbound call: %s", message.start_line)

    def _wait_for_ack(self, dialog: SipDialog, invite: SipMessage, local_tag: str) -> None:
        deadline = time.monotonic() + self.config.call.setup_timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError("Timed out waiting for ACK to incoming INVITE")
            message = self.transport.receive(timeout_seconds=remaining)
            if message.status_code is not None:
                LOGGER.info("Ignoring SIP response while waiting for ACK: %s", message.start_line)
                continue
            if message.method == "ACK":
                return
            if message.method == "CANCEL":
                self._answer_cancel(message, invite, local_tag)
                raise IncomingCallCancelled()
            if message.method == "BYE":
                self.transport.send(self.builder.ok_response(message))
                raise SipError("Remote sent BYE before ACK")
            LOGGER.info("Ignoring request while waiting for ACK: %s", message.start_line)

    def _answer_cancel(self, cancel: SipMessage, invite: SipMessage, local_tag: str) -> None:
        LOGGER.info("Received CANCEL for inbound INVITE")
        self.transport.send(self.builder.ok_response(cancel, to_tag=local_tag))
        self.transport.send(
            self.builder.response_to_request(
                invite,
                status_code=487,
                reason="Request Terminated",
                to_tag=local_tag,
            )
        )
        LOGGER.info("Answered CANCEL with 200 OK and original INVITE with 487")

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
            remote_media,
            sock=rtp_sock,
            close_socket_on_stop=True,
        )
        receiver.start()
        sender.start()
        return sender, receiver

    def bye(self, ids: SipSessionIds, dialog: SipDialog, *, timeout_seconds: float | None = None) -> SipMessage | None:
        self.transport.send(
            self.builder.bye(
                ids,
                dialog.dialog_to,
                dialog.route_set,
                request_uri=dialog.request_uri(self.config.call.target_uri),
            )
        )
        while True:
            try:
                response = self.transport.receive(timeout_seconds=timeout_seconds)
            except SipReceiveTimeout:
                LOGGER.warning("Timed out waiting for 200 OK to BYE")
                return None
            if response.status_code == 200 and response.method == "BYE":
                return response
            if response.method == "BYE" and response.status_code is None:
                self._handle_in_dialog_request(response)

    def drain_pending_sip(self, *, max_seconds: float = 1.0) -> None:
        deadline = time.monotonic() + max_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                message = self.transport.receive(timeout_seconds=min(0.2, remaining))
            except SipReceiveTimeout:
                return
            except SipError as exc:
                LOGGER.info("Stopped draining SIP messages: %s", exc)
                return

            LOGGER.info("Drained pending SIP message before shutdown: %s", message.start_line)
            if message.status_code is None and message.method == "BYE":
                self.transport.send(self.builder.ok_response(message))
                LOGGER.info("Answered drained BYE with 200 OK")

    def poll_during_media(
        self,
        ids: SipSessionIds,
        dialog: SipDialog,
        *,
        sender: RtpSender,
        receiver: RtpReceiver,
        timeout_seconds: float = 0.5,
    ) -> bool:
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
            if message.body:
                remote_media = parse_remote_sdp(message.body)
                sdp_answer = build_amrwb_offer(
                    self.config,
                    self.local_ip,
                    octet_align=remote_media.octet_aligned,
                    payload_type=remote_media.payload_type,
                )
                self.transport.send(self.builder.ok_response(message, body=sdp_answer, ids=ids))
                self._apply_remote_media(remote_media, sender, receiver, source="re-INVITE offer")
                self._awaiting_reinvite_answer = False
                LOGGER.info("Answered re-INVITE SDP offer with 200 OK SDP answer")
            else:
                sdp_offer = build_amrwb_offer(
                    self.config,
                    self.local_ip,
                    octet_align=sender.octet_aligned,
                    payload_type=sender.payload_type,
                )
                self.transport.send(self.builder.ok_response(message, body=sdp_offer, ids=ids))
                self._awaiting_reinvite_answer = True
                LOGGER.info("Answered offerless re-INVITE with 200 OK SDP offer; waiting for ACK SDP answer")
            return True
        if method == "UPDATE":
            self.transport.send(self.builder.ok_response(message, ids=ids))
            LOGGER.info("Answered UPDATE with 200 OK")
            return True
        if method == "ACK":
            if self._awaiting_reinvite_answer and message.body:
                remote_media = parse_remote_sdp(message.body)
                self._apply_remote_media(remote_media, sender, receiver, source="ACK SDP answer")
                self._awaiting_reinvite_answer = False
            elif self._awaiting_reinvite_answer:
                LOGGER.warning("ACK for offerless re-INVITE had no SDP answer; keeping current RTP settings")
                self._awaiting_reinvite_answer = False
            LOGGER.info("Received ACK for in-dialog transaction")
            return True
        if method == "BYE":
            self.transport.send(self.builder.ok_response(message))
            LOGGER.info("Remote side ended the call with BYE")
            return False

        LOGGER.info("Ignoring unsupported in-dialog request: %s", message.start_line)
        return True

    def _apply_remote_media(
        self,
        remote_media: RemoteMedia,
        sender: RtpSender,
        receiver: RtpReceiver,
        *,
        source: str,
    ) -> None:
        LOGGER.warning(
            "Applying negotiated media from %s: remote=%s:%s PT=%s octet_align=%s direction=%s",
            source,
            remote_media.ip,
            remote_media.port,
            remote_media.payload_type,
            remote_media.octet_aligned,
            remote_media.direction,
        )
        sender.update_remote_media(remote_media)
        receiver.update_remote_media(remote_media)

    def close(self) -> None:
        self.transport.close()

    def _handle_in_dialog_request(self, request: SipMessage) -> None:
        if request.method == "BYE":
            self.transport.send(self.builder.ok_response(request))
            raise SipError("Remote side ended the call with BYE")
        LOGGER.info("Ignoring in-dialog request for first demo version: %s", request.start_line)
