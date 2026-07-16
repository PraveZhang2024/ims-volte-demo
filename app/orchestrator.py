"""Top-level orchestration for the IMS VoLTE demo client."""

from __future__ import annotations

import logging
import time

from app.config import AppConfig
from app.state import ClientState
from ipsec.xfrm_manager import XfrmManager
from network.interface import InterfaceResolver
from network.route import RouteChecker
from sip.call import ImsCallClient
from sip.register import ImsRegistrationClient, RegistrationResult
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
        interface = InterfaceResolver(self.command_runner).get_ipv4(self.config.network.interface)
        if not interface.is_up:
            LOGGER.warning("IMS interface %s is not marked UP", interface.name)
        route_checker = RouteChecker(self.command_runner)
        route_checker.check_route(self.config.network.pcscf_ip, self.config.network.interface)
        route_checker.check_tcp_connect(
            local_ip=interface.ipv4,
            local_port=0,
            remote_ip=self.config.network.pcscf_ip,
            remote_port=self.config.network.pcscf_port,
            timeout_seconds=self.config.network.connect_timeout_seconds,
        )
        self._set_state(ClientState.NETWORK_READY)
        return interface.ipv4

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

    def run_call(self) -> None:
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
            media_until = time.monotonic() + self.config.call.duration_seconds
            while time.monotonic() < media_until:
                keep_running = call_client.poll_during_media(
                    registration.ids,
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
                        registration.ids,
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

    def _capture(self) -> TcpdumpCapture:
        return TcpdumpCapture(
            interface=self.config.network.interface,
            output_dir=self.config.base_dir / "captures",
            enabled=self.config.debug.capture_pcap,
        )

    def _set_state(self, state: ClientState) -> None:
        self.state = state
        LOGGER.info("State -> %s", state.value)
