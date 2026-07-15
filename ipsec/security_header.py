"""IMS Security-Client, Security-Server, and Security-Verify helpers."""

from __future__ import annotations

from dataclasses import dataclass
import secrets


@dataclass(frozen=True)
class SecurityAssociation:
    mechanism: str = "ipsec-3gpp"
    alg: str = "hmac-md5-96"
    ealg: str = "null"
    prot: str = "esp"
    mode: str = "trans"
    spi_c: int = 0
    spi_s: int = 0
    port_c: int = 0
    port_s: int = 0
    q: str | None = None

    @classmethod
    def local(cls, local_spi: int, local_port: int, remote_port: int) -> "SecurityAssociation":
        return cls(spi_c=local_spi, spi_s=local_spi, port_c=local_port, port_s=remote_port, q="0.1")

    @classmethod
    def parse(cls, value: str) -> "SecurityAssociation":
        value = split_security_header(value)[0]
        mechanism, *parts = [part.strip() for part in value.split(";") if part.strip()]
        params: dict[str, str] = {}
        for part in parts:
            if "=" not in part:
                continue
            key, val = part.split("=", 1)
            params[key.strip().lower()] = val.strip().strip('"')

        return cls(
            mechanism=mechanism,
            alg=params.get("alg", "hmac-md5-96"),
            ealg=params.get("ealg", "null"),
            prot=params.get("prot", "esp"),
            mode=params.get("mod", params.get("mode", "trans")),
            spi_c=_int_param(params, "spi-c"),
            spi_s=_int_param(params, "spi-s"),
            port_c=_int_param(params, "port-c"),
            port_s=_int_param(params, "port-s"),
            q=params.get("q"),
        )

    def to_header_value(self, *, include_q: bool = True) -> str:
        params = [
            f"alg={self.alg}",
            f"ealg={self.ealg}",
            f"prot={self.prot}",
            f"mod={self.mode}",
            f"spi-c={self.spi_c}",
            f"spi-s={self.spi_s}",
            f"port-c={self.port_c}",
            f"port-s={self.port_s}",
        ]
        if include_q and self.q:
            params.append(f"q={self.q}")
        return self.mechanism + ";" + ";".join(params)


def generate_spi() -> int:
    return secrets.randbelow(0xEFFFFFFF - 0x1000) + 0x1000


def build_security_client(local_port: int, remote_port: int) -> SecurityAssociation:
    return SecurityAssociation.local(
        local_spi=generate_spi(),
        local_port=local_port,
        remote_port=remote_port,
    )


def build_security_client_header(
    *,
    local_port: int,
    remote_port: int,
    algorithms: list[str],
    encryption_algorithms: list[str],
) -> tuple[SecurityAssociation, str]:
    base = build_security_client(local_port, remote_port)
    proposals = [
        SecurityAssociation(
            alg=alg,
            ealg=ealg,
            spi_c=base.spi_c,
            spi_s=base.spi_s,
            port_c=base.port_c,
            port_s=base.port_s,
            q=base.q,
        ).to_header_value(include_q=False)
        for alg in algorithms
        for ealg in encryption_algorithms
    ]
    return base, ",".join(proposals)


def build_security_verify(server: SecurityAssociation) -> str:
    return server.to_header_value(include_q=False)


def split_security_header(value: str) -> list[str]:
    parts: list[str] = []
    token = ""
    in_quote = False
    for char in value:
        if char == '"':
            in_quote = not in_quote
        if char == "," and not in_quote:
            if token.strip():
                parts.append(token.strip())
            token = ""
        else:
            token += char
    if token.strip():
        parts.append(token.strip())
    return parts


def _int_param(params: dict[str, str], name: str) -> int:
    value = params.get(name, "0")
    return int(value, 0)
