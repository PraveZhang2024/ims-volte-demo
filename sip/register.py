"""IMS SIP registration flow."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import secrets

from aka.digest_akav1 import DigestCredentials, build_authorization, digest_debug
from aka.milenage_service import AkaChallenge, AkaResult, MilenageService
from app.config import AppConfig
from app.errors import SipError
from ipsec.security_header import (
    SecurityAssociation,
    build_security_client_header,
    build_security_verify,
    split_security_header,
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
        local_security, security_client_header = build_security_client_header(
            local_port=self.config.network.local_protected_port,
            remote_port=self.config.network.pcscf_port,
            algorithms=self.config.ims.security_client_algorithms,
            encryption_algorithms=self.config.ims.security_client_encryption_algorithms,
        )
        first_response = self._send_initial_register(ids, local_security, security_client_header)
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
        security_client_header: str,
    ) -> SipMessage:
        builder = SipBuilder(self.config, self.local_ip, protected=False)
        message = builder.register(ids, security_client=security_client_header)
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
            for proposal in split_security_header(value):
                if proposal.lower().startswith("ipsec-3gpp"):
                    return SecurityAssociation.parse(proposal)
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
        request_uri = f"sip:{self.config.subscriber.realm}"
        cnonce = secrets.token_hex(8) if qop else ""
        credentials = DigestCredentials(
            username=self.config.subscriber.impi,
            realm=realm,
            uri=request_uri,
            method="REGISTER",
            password=self._digest_password(aka_result),
            nonce=params["nonce"],
            algorithm=params.get("algorithm", "AKAv1-MD5"),
            qop=qop,
            opaque=params.get("opaque"),
            cnonce=cnonce,
        )
        LOGGER.info("REGISTER digest uri=%s realm=%s", request_uri, realm)
        self._log_digest_inputs("selected", self.config.ims.digest_res_encoding, credentials)
        self._log_digest_candidates(params, aka_result, request_uri, realm, qop, cnonce)
        return build_authorization(credentials)

    def _digest_password(self, aka_result: AkaResult) -> str | bytes:
        encoding = self.config.ims.digest_res_encoding
        if encoding == "hex_lower":
            return aka_result.res_hex
        if encoding == "hex_upper":
            return aka_result.res_hex.upper()
        if encoding == "raw":
            return aka_result.res
        raise SipError(f"Unsupported ims.digest_res_encoding: {encoding}")

    def _log_digest_candidates(
        self,
        params: dict[str, str],
        aka_result: AkaResult,
        request_uri: str,
        realm: str,
        qop: str | None,
        cnonce: str,
    ) -> None:
        # S-CSCF logs often include the expected digest response. These variants
        # make it possible to align the local RES encoding without packet guessing.
        for label, password in (
            ("hex_lower", aka_result.res_hex),
            ("hex_upper", aka_result.res_hex.upper()),
            ("raw", aka_result.res),
        ):
            credentials = DigestCredentials(
                username=self.config.subscriber.impi,
                realm=realm,
                uri=request_uri,
                method="REGISTER",
                password=password,
                nonce=params["nonce"],
                algorithm=params.get("algorithm", "AKAv1-MD5"),
                qop=qop,
                opaque=params.get("opaque"),
                cnonce=cnonce,
            )
            self._log_digest_inputs("candidate", label, credentials)

    def _log_digest_inputs(self, kind: str, label: str, credentials: DigestCredentials) -> None:
        debug = digest_debug(credentials)
        LOGGER.info(
            "Digest %s res_encoding=%s username=%s realm=%s nonce=%s uri=%s method=%s "
            "algorithm=%s qop=%s nc=%s cnonce=%s opaque=%s",
            kind,
            label,
            debug.username,
            debug.realm,
            debug.nonce,
            debug.uri,
            debug.method,
            debug.algorithm,
            debug.qop,
            debug.nc,
            debug.cnonce,
            debug.opaque,
        )
        LOGGER.info(
            "Digest %s res_encoding=%s password_mode=%s password=%s",
            kind,
            label,
            debug.password_mode,
            debug.password_debug,
        )
        LOGGER.info(
            "Digest %s res_encoding=%s HA1_input=%s HA1=%s",
            kind,
            label,
            debug.ha1_input_debug,
            debug.ha1,
        )
        LOGGER.info(
            "Digest %s res_encoding=%s HA2_input=%s HA2=%s",
            kind,
            label,
            debug.ha2_input,
            debug.ha2,
        )
        LOGGER.info(
            "Digest %s res_encoding=%s response_input=%s response=%s",
            kind,
            label,
            debug.response_input,
            debug.response,
        )
