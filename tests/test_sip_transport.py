from types import SimpleNamespace

from sip.parser import parse_sip_message
from sip.register import ImsRegistrationClient
from sip.transport import SipTcpTransport


class FakeSocket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.timeout = 1.0
        self.recv_calls = 0

    def gettimeout(self) -> float:
        return self.timeout

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        self.recv_calls += 1
        payload, self.payload = self.payload, b""
        return payload


class FakeTransport:
    def __init__(self, responses: list) -> None:
        self.responses = iter(responses)

    def receive(self, *, timeout_seconds: float | None = None):
        return next(self.responses)


def sip_response(status: str) -> bytes:
    return (
        f"SIP/2.0 {status}\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()


def test_transport_preserves_coalesced_messages():
    fake_socket = FakeSocket(sip_response("100 Trying") + sip_response("401 Unauthorized"))
    transport = SipTcpTransport(
        local_ip="127.0.0.1",
        local_port=5060,
        remote_ip="127.0.0.2",
        remote_port=5060,
        timeout_seconds=1.0,
        dump_sip=False,
    )
    transport._sock = fake_socket  # type: ignore[assignment]

    assert transport.receive().status_code == 100
    assert transport.receive().status_code == 401
    assert fake_socket.recv_calls == 1


def test_register_waits_through_provisional_response():
    client = ImsRegistrationClient.__new__(ImsRegistrationClient)
    client.config = SimpleNamespace(network=SimpleNamespace(connect_timeout_seconds=1.0))
    responses = [
        parse_sip_message(sip_response("100 Trying")),
        parse_sip_message(sip_response("401 Unauthorized")),
    ]

    response = client._receive_final_register_response(FakeTransport(responses))  # type: ignore[arg-type]

    assert response.status_code == 401
