"""SIP dialog state extracted from IMS responses."""

from __future__ import annotations

from dataclasses import dataclass, field

from sip.message import SipMessage


@dataclass
class SipDialog:
    call_id: str
    local_tag: str
    remote_tag: str = ""
    route_set: list[str] = field(default_factory=list)
    remote_target: str = ""
    dialog_to: str = ""

    def update_from_response(self, response: SipMessage) -> None:
        to_value = response.get("To", "") or ""
        self.dialog_to = to_value
        if ";tag=" in to_value and not self.remote_tag:
            self.remote_tag = to_value.split(";tag=", 1)[1].split(";", 1)[0]
        contact = response.get("Contact")
        if contact:
            self.remote_target = extract_sip_uri(contact)
        record_routes = response.get_all("Record-Route")
        if record_routes:
            self.route_set = list(reversed(record_routes))

    def request_uri(self, fallback: str) -> str:
        return self.remote_target or fallback

    @classmethod
    def from_incoming_invite(cls, request: SipMessage, *, local_tag: str) -> "SipDialog":
        from_value = request.get("From", "") or ""
        remote_tag = ""
        if ";tag=" in from_value:
            remote_tag = from_value.split(";tag=", 1)[1].split(";", 1)[0]
        contact = request.get("Contact", "") or ""
        return cls(
            call_id=request.get("Call-ID", "") or "",
            local_tag=local_tag,
            remote_tag=remote_tag,
            route_set=request.get_all("Record-Route"),
            remote_target=extract_sip_uri(contact) if contact else "",
            dialog_to=from_value,
        )


def rack_from_response(response: SipMessage) -> str | None:
    rseq = response.get("RSeq")
    cseq = response.get("CSeq")
    if not rseq or not cseq:
        return None
    cseq_parts = cseq.split()
    if len(cseq_parts) < 2:
        return None
    return f"{rseq} {cseq_parts[0]} {cseq_parts[1]}"


def extract_sip_uri(value: str) -> str:
    value = value.strip()
    if "<" in value and ">" in value:
        return value.split("<", 1)[1].split(">", 1)[0].strip()
    return value.split(";", 1)[0].strip()
