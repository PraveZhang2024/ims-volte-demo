"""SIP request builders for the fixed IMS demo flow."""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets

from app.config import AppConfig
from sip.message import SipMessage


def new_branch() -> str:
    return "z9hG4bK" + secrets.token_hex(8)


def new_tag() -> str:
    return secrets.token_hex(8)


def new_call_id(local_ip: str) -> str:
    return f"{secrets.token_hex(12)}@{local_ip}"


@dataclass
class SipSessionIds:
    local_ip: str
    call_id: str = ""
    from_tag: str = field(default_factory=new_tag)
    cseq: int = 1
    method_cseq: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.call_id:
            self.call_id = new_call_id(self.local_ip)

    def next_cseq(self) -> int:
        current = self.cseq
        self.cseq += 1
        return current

    def remember_cseq(self, method: str, cseq: int) -> None:
        self.method_cseq[method.upper()] = cseq

    def cseq_for(self, method: str) -> int:
        return self.method_cseq[method.upper()]


class SipBuilder:
    def __init__(self, config: AppConfig, local_ip: str, protected: bool = False) -> None:
        self.config = config
        self.local_ip = local_ip
        self.protected = protected

    @property
    def local_sip_port(self) -> int:
        if self.protected:
            return self.config.network.local_protected_port
        return self.config.network.local_sip_port

    def register(
        self,
        ids: SipSessionIds,
        *,
        authorization: str | None = None,
        security_client: str | None = None,
        security_verify: str | None = None,
        expires: int = 3600,
    ) -> SipMessage:
        impu = self.config.subscriber.impu
        realm = self.config.subscriber.realm
        msg = SipMessage(f"REGISTER sip:{realm} SIP/2.0")
        self._base_headers(msg, ids, "REGISTER", impu)
        msg.add_header("To", f"<{impu}>")
        msg.add_header("Contact", self._contact(expires=expires))
        msg.add_header("Expires", str(expires))
        msg.add_header("Supported", "path, sec-agree")
        msg.add_header("Require", "sec-agree")
        msg.add_header("Proxy-Require", "sec-agree")
        msg.add_header("P-Access-Network-Info", "3GPP-E-UTRAN-FDD")
        if security_client:
            msg.add_header("Security-Client", security_client)
        if authorization:
            msg.add_header("Authorization", authorization)
        if security_verify:
            msg.add_header("Security-Verify", security_verify)
        return msg

    def invite(
        self,
        ids: SipSessionIds,
        sdp_body: str,
        *,
        route_set: list[str] | None = None,
    ) -> SipMessage:
        target = self.config.call.target_uri
        msg = SipMessage(f"INVITE {target} SIP/2.0", body=sdp_body)
        self._base_headers(msg, ids, "INVITE", target, route_set=route_set)
        msg.add_header("To", f"<{target}>")
        msg.add_header("Contact", self._contact())
        msg.add_header("P-Preferred-Identity", f"<{self.config.subscriber.impu}>")
        msg.add_header("Supported", "100rel, timer")
        msg.add_header("Allow", "INVITE, ACK, PRACK, BYE, CANCEL, UPDATE")
        msg.add_header("Content-Type", "application/sdp")
        return msg

    def prack(self, ids: SipSessionIds, dialog_to: str, rack: str, route_set: list[str]) -> SipMessage:
        target = self.config.call.target_uri
        msg = SipMessage(f"PRACK {target} SIP/2.0")
        self._base_headers(msg, ids, "PRACK", target, route_set=route_set)
        msg.add_header("To", dialog_to)
        msg.add_header("RAck", rack)
        return msg

    def ack(self, ids: SipSessionIds, dialog_to: str, route_set: list[str]) -> SipMessage:
        target = self.config.call.target_uri
        msg = SipMessage(f"ACK {target} SIP/2.0")
        self._base_headers(
            msg,
            ids,
            "ACK",
            target,
            route_set=route_set,
            reuse_cseq=True,
            reuse_cseq_method="INVITE",
        )
        msg.add_header("To", dialog_to)
        return msg

    def bye(self, ids: SipSessionIds, dialog_to: str, route_set: list[str]) -> SipMessage:
        target = self.config.call.target_uri
        msg = SipMessage(f"BYE {target} SIP/2.0")
        self._base_headers(msg, ids, "BYE", target, route_set=route_set)
        msg.add_header("To", dialog_to)
        return msg

    def ok_response(self, request: SipMessage) -> SipMessage:
        msg = SipMessage("SIP/2.0 200 OK")
        for header in ("Via", "From", "To", "Call-ID", "CSeq"):
            for value in request.get_all(header):
                msg.add_header(header, value)
        return msg

    def _base_headers(
        self,
        msg: SipMessage,
        ids: SipSessionIds,
        method: str,
        remote_uri: str,
        *,
        route_set: list[str] | None = None,
        reuse_cseq: bool = False,
        reuse_cseq_method: str | None = None,
    ) -> None:
        for route in route_set or []:
            msg.add_header("Route", route)
        msg.add_header("Via", f"SIP/2.0/TCP {self.local_ip}:{self.local_sip_port};branch={new_branch()}")
        msg.add_header("Max-Forwards", "70")
        msg.add_header("From", f"\"{self.config.call.local_display_name}\" <{self.config.subscriber.impu}>;tag={ids.from_tag}")
        msg.add_header("Call-ID", ids.call_id)
        cseq = ids.cseq_for(reuse_cseq_method or method) if reuse_cseq else ids.next_cseq()
        ids.remember_cseq(method, cseq)
        msg.add_header("CSeq", f"{cseq} {method}")
        msg.add_header("User-Agent", self.config.call.user_agent)

    def _contact(self, *, expires: int | None = None) -> str:
        features = "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
        value = f"<sip:{self.config.subscriber.impi};transport=tcp>;{features}"
        if expires is not None:
            value += f";expires={expires}"
        return value
