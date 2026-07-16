"""Top-level orchestration for the IMS VoLTE demo client."""

from __future__ import annotations

import logging
import socket
import time

from app.config import AppConfig
from app.state import ClientState
from ipsec.xfrm_manager import XfrmManager
from network.interface import InterfaceResolver
from network.route import RouteChecker
from sip.call import ImsCallClient
from sip.register import ImsRegistrationClient, RegistrationResult
from sip.sms import ImsSmsClient
from tools.capture import TcpdumpCapture
from tools.command import CommandRunner

LOGGER = logging.getLogger(__name__)


class ImsVolteOrchestrator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.state = ClientState.INIT
        self.command_runner = CommandRunner(
            execute=True,
            timeout_seconds=config.debug.command_timeout_seconds,
        )
        self.xfrm_runner = CommandRunner(
            execute=config.debug.execute_xfrm_commands,
            timeout_seconds=config.debug.command_timeout_seconds,
        )
        self.xfrm_manager = XfrmManager(self.xfrm_runner)

    def print_summary(self) -> None:
        for line in self.config.summary_lines():
            print(line)

    def network_check(self) -> str:
        route_checker = RouteChecker(self.command_runner)
        if self.config.network.interface:
            interface = InterfaceResolver(self.command_runner).get_ipv4(self.config.network.interface)
            if not interface.is_up:
                LOGGER.warning("IMS interface %s is not marked UP", interface.name)
            route_checker.check_route(self.config.network.pcscf_ip, self.config.network.interface)
            local_ip = interface.ipv4
        else:
            LOGGER.info("No IMS interface specified; using system default route")
            route_checker.log_route(self.config.network.pcscf_ip)
            local_ip = self._default_source_ip(self.config.network.pcscf_ip, self.config.network.pcscf_port)
        route_checker.check_tcp_connect(
            local_ip=local_ip,
            local_port=0,
            remote_ip=self.config.network.pcscf_ip,
            remote_port=self.config.network.pcscf_port,
            timeout_seconds=self.config.network.connect_timeout_seconds,
        )
        self._set_state(ClientState.NETWORK_READY)
        return local_ip

    def register(
        self,
        *,
        cleanup_on_exit: bool = True,
        manage_capture: bool = True,
    ) -> RegistrationResult:
        local_ip = self.network_check()
        capture = self._capture() if manage_capture else None
        if capture:
            capture.start()
        try:
            client = ImsRegistrationClient(
                config=self.config,
                local_ip=local_ip,
                xfrm_manager=self.xfrm_manager,
            )
            self._set_state(ClientState.TCP_CONNECTED)
            result = client.perform()
            if result.stopped_before_protected_register:
                self._set_state(ClientState.IPSEC_READY)
            elif result.registered:
                self._set_state(ClientState.REGISTERED)
            return result
        finally:
            if capture:
                capture.stop()
            if cleanup_on_exit:
                self.xfrm_manager.cleanup_all()

    def run_call(self, *, duration_seconds: float) -> None:
        capture = self._capture()
        capture.start()
        sender = None
        receiver = None
        call_client = None
        registration = None
        call = None
        remote_ended = False
        try:
            registration = self.register(cleanup_on_exit=False, manage_capture=False)
            if not registration.registered:
                LOGGER.warning("Registration did not complete; call setup is skipped")
                return

            local_ip = registration.ids.local_ip
            call_client = ImsCallClient(self.config, local_ip, transport=registration.protected_transport)
            self._set_state(ClientState.INVITE_SENT)
            call = call_client.establish(registration.ids, registration.service_routes)
            self._set_state(ClientState.CALL_ESTABLISHED)

            sender, receiver = call_client.run_media(call.remote_media)
            self._set_state(ClientState.MEDIA_RUNNING)
            effective_duration = duration_seconds
            if effective_duration <= 0:
                LOGGER.info("Call duration is unlimited; media loops until remote BYE or signal")
                media_until = None
            else:
                LOGGER.info("Call duration: %s seconds", effective_duration)
                media_until = time.monotonic() + effective_duration

            while media_until is None or time.monotonic() < media_until:
                keep_running = call_client.poll_during_media(
                    call.ids,
                    call.dialog,
                    timeout_seconds=0.5,
                )
                if not keep_running:
                    remote_ended = True
                    break
        finally:
            if call is not None:
                self._set_state(ClientState.TERMINATING)
            if sender:
                sender.stop()
            if call_client and registration and call and not remote_ended:
                try:
                    call_client.bye(
                        call.ids,
                        call.dialog,
                        timeout_seconds=self.config.network.connect_timeout_seconds,
                    )
                except Exception as exc:
                    LOGGER.warning("Failed to send BYE during shutdown: %s", exc)
            if call_client:
                call_client.drain_pending_sip(max_seconds=1.0)
            if receiver:
                receiver.stop()
            if call_client:
                call_client.close()
            self.xfrm_manager.cleanup_all()
            capture.stop()
            if call is not None:
                self._set_state(ClientState.TERMINATED)

    def run_send_sms(self, *, smsc: str, target_msisdn: str, content: str) -> None:
        capture = self._capture()
        capture.start()
        sms_client = None
        registration = None
        try:
            registration = self.register(cleanup_on_exit=False, manage_capture=False)
            if not registration.registered:
                LOGGER.warning("Registration did not complete; send-sms mode is skipped")
                return

            local_ip = registration.ids.local_ip
            sms_client = ImsSmsClient(self.config, local_ip, transport=registration.protected_transport)
            self._set_state(ClientState.SMS_SENT)
            sms_client.send_sms(
                registration.ids,
                smsc=smsc,
                target_msisdn=target_msisdn,
                content=content,
                service_routes=registration.service_routes,
            )
            self._set_state(ClientState.SMS_ACCEPTED)
        finally:
            if sms_client:
                sms_client.close()
            elif registration and registration.protected_transport:
                registration.protected_transport.close()
            self.xfrm_manager.cleanup_all()
            capture.stop()

    def run_listen(self) -> None:
        capture = self._capture()
        capture.start()
        sender = None
        receiver = None
        call_client = None
        registration = None
        call = None
        remote_ended = False
        try:
            registration = self.register(cleanup_on_exit=False, manage_capture=False)
            if not registration.registered:
                LOGGER.warning("Registration did not complete; listen mode is skipped")
                return

            LOGGER.info("Protected SIP connection established; waiting for inbound call")
            local_ip = registration.ids.local_ip
            call_client = ImsCallClient(self.config, local_ip, transport=registration.protected_transport)
            call = call_client.wait_for_incoming_call(registration.ids)
            self._set_state(ClientState.CALL_ESTABLISHED)

            sender, receiver = call_client.run_media(call.remote_media)
            self._set_state(ClientState.MEDIA_RUNNING)
            while True:
                keep_running = call_client.poll_during_media(
                    call.ids,
                    call.dialog,
                    timeout_seconds=0.5,
                )
                if not keep_running:
                    remote_ended = True
                    break
        finally:
            if call is not None:
                self._set_state(ClientState.TERMINATING)
            if sender:
                sender.stop()
            if call_client and registration and call and not remote_ended:
                try:
                    call_client.bye(
                        call.ids,
                        call.dialog,
                        timeout_seconds=self.config.network.connect_timeout_seconds,
                    )
                except Exception as exc:
                    LOGGER.warning("Failed to send BYE during listen shutdown: %s", exc)
            if call_client:
                call_client.drain_pending_sip(max_seconds=1.0)
            if receiver:
                receiver.stop()
            if call_client:
                call_client.close()
            self.xfrm_manager.cleanup_all()
            capture.stop()
            if call is not None:
                self._set_state(ClientState.TERMINATED)

    def _capture(self) -> TcpdumpCapture:
        return TcpdumpCapture(
            interface=self.config.network.interface,
            output_dir=self.config.base_dir / "captures",
            enabled=self.config.debug.capture_pcap,
        )

    def _set_state(self, state: ClientState) -> None:
        self.state = state
        LOGGER.info("State -> %s", state.value)

    def _default_source_ip(self, remote_ip: str, remote_port: int) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((remote_ip, remote_port))
            local_ip = sock.getsockname()[0]
            LOGGER.info("Resolved default-route local IP for P-CSCF: %s", local_ip)
            return local_ip
        finally:
            sock.close()
