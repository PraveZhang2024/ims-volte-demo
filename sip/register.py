"""IMS SIP registration flow."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging

from aka.digest_akav1 import DigestCredentials, build_authorization
from aka.milenage_service import AkaChallenge, AkaResult, MilenageService
from app.config import AppConfig
from app.errors import SipError
from ipsec.security_header import (
    SecurityAssociation,
    build_security_client,
    build_security_verify,
)
from ipsec.xfrm_manager import XfrmContext, XfrmManager
from sip.builder import SipBuilder, SipSessionIds
from sip.message import SipMessage
from sip.parser import parse_auth_params
from sip.transport import SipTcpTransport

LOGGER = logging.getLogger(__name__)


@dataclass
class RegistrationResult:
    registered: bool
    ids: SipSessionIds
    service_routes: list[str] = field(default_factory=list)
    associated_uris: list[str] = field(default_factory=list)
    local_security: SecurityAssociation | None = None
    server_security: SecurityAssociation | None = None
    aka_result: AkaResult | None = None
    xfrm_context: XfrmContext | None = None
    final_response: SipMessage | None = None
    stopped_before_protected_register: bool = False


class ImsRegistrationClient:
    def __init__(
        self,
        *,
        config: AppConfig,
        local_ip: str,
        xfrm_manager: XfrmManager,
    ) -> None:
        self.config = config
        self.local_ip = local_ip
        self.xfrm_manager = xfrm_manager

    def perform(self) -> RegistrationResult:
        ids = SipSessionIds(local_ip=self.local_ip)
        local_security = build_security_client(
            local_port=self.config.network.local_protected_port,
            remote_port=self.config.network.pcscf_port,
        )
        first_response = self._send_initial_register(ids, local_security)
        if first_response.status_code != 401:
            raise SipError(f"Expected 401 Unauthorized, got {first_response.start_line}")

        server_security = self._parse_security_server(first_response)
        digest_params = self._parse_www_authenticate(first_response)
        aka_result = self._compute_aka(digest_params["nonce"])
        authorization = self._authorization(digest_params, aka_result)

        xfrm_context = self.xfrm_manager.build_context(
            ue_ip=self.local_ip,
            pcscf_ip=self.config.network.pcscf_ip,
            local_clear_port=self.config.network.local_sip_port,
            local_protected_port=self.config.network.local_protected_port,
            local_security=local_security,
            server_security=server_security,
            ck_hex=aka_result.ck_hex,
            ik_hex=aka_result.ik_hex,
        )
        self.xfrm_manager.setup(xfrm_context)

        if not self.config.debug.execute_xfrm_commands:
            LOGGER.warning("XFRM is dry-run; protected REGISTER was not sent")
            return RegistrationResult(
                registered=False,
                ids=ids,
                local_security=local_security,
                server_security=server_security,
                aka_result=aka_result,
                xfrm_context=xfrm_context,
                stopped_before_protected_register=True,
            )

        final_response = self._send_protected_register(
            ids=ids,
            authorization=authorization,
            security_verify=build_security_verify(server_security),
        )
        if final_response.status_code != 200:
            raise SipError(f"Expected 200 OK for protected REGISTER, got {final_response.start_line}")

        return RegistrationResult(
            registered=True,
            ids=ids,
            service_routes=final_response.get_all("Service-Route"),
            associated_uris=final_response.get_all("P-Associated-URI"),
            local_security=local_security,
            server_security=server_security,
            aka_result=aka_result,
            xfrm_context=xfrm_context,
            final_response=final_response,
        )

    def _send_initial_register(
        self,
        ids: SipSessionIds,
        local_security: SecurityAssociation,
    ) -> SipMessage:
        builder = SipBuilder(self.config, self.local_ip, protected=False)
        message = builder.register(ids, security_client=local_security.to_header_value())
        transport = self._transport(local_port=self.config.network.local_sip_port)
        try:
            transport.connect()
            transport.send(message)
            return transport.receive()
        finally:
            transport.close()

    def _send_protected_register(
        self,
        *,
        ids: SipSessionIds,
        authorization: str,
        security_verify: str,
    ) -> SipMessage:
        builder = SipBuilder(self.config, self.local_ip, protected=True)
        message = builder.register(
            ids,
            authorization=authorization,
            security_verify=security_verify,
        )
        transport = self._transport(local_port=self.config.network.local_protected_port)
        try:
            transport.connect()
            transport.send(message)
            return transport.receive()
        finally:
            transport.close()

    def _transport(self, local_port: int) -> SipTcpTransport:
        return SipTcpTransport(
            local_ip=self.local_ip,
            local_port=local_port,
            remote_ip=self.config.network.pcscf_ip,
            remote_port=self.config.network.pcscf_port,
            timeout_seconds=self.config.network.connect_timeout_seconds,
            dump_sip=self.config.debug.dump_sip,
        )

    def _parse_www_authenticate(self, response: SipMessage) -> dict[str, str]:
        values = response.get_all("WWW-Authenticate")
        for value in values:
            if "AKAv1-MD5" in value or value.lower().startswith("digest"):
                params = parse_auth_params(value)
                if "nonce" not in params:
                    raise SipError("WWW-Authenticate is missing nonce")
                return params
        raise SipError("401 response has no supported WWW-Authenticate header")

    def _parse_security_server(self, response: SipMessage) -> SecurityAssociation:
        values = response.get_all("Security-Server")
        for value in values:
            if value.lower().startswith("ipsec-3gpp"):
                return SecurityAssociation.parse(value)
        raise SipError("401 response has no ipsec-3gpp Security-Server header")

    def _compute_aka(self, nonce: str) -> AkaResult:
        challenge = AkaChallenge.from_nonce(nonce)
        service = MilenageService(self.config.subscriber.k, self.config.subscriber.opc)
        result = service.compute(challenge)
        if not result.mac_verified:
            raise SipError("AKA AUTN MAC verification failed")
        LOGGER.info("AKA RES=%s CK=%s IK=%s", result.res_hex, result.ck_hex, result.ik_hex)
        return result

    def _authorization(self, params: dict[str, str], aka_result: AkaResult) -> str:
        realm = params.get("realm") or self.config.subscriber.realm
        qop = params.get("qop")
        if qop and "," in qop:
            qop = "auth" if "auth" in [part.strip() for part in qop.split(",")] else qop.split(",")[0]
        credentials = DigestCredentials(
            username=self.config.subscriber.impi,
            realm=realm,
            uri=f"sip:{realm}",
            method="REGISTER",
            res_hex=aka_result.res_hex,
            nonce=params["nonce"],
            algorithm=params.get("algorithm", "AKAv1-MD5"),
            qop=qop,
            opaque=params.get("opaque"),
        )
        return build_authorization(credentials)
