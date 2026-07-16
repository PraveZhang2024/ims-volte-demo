"""YAML configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import socket
from typing import Any
import uuid

import yaml

from app.errors import ConfigError


@dataclass(frozen=True)
class NetworkConfig:
    interface: str
    pcscf_ip: str
    pcscf_port: int
    local_sip_port: int
    local_protected_port: int
    local_rtp_port: int
    connect_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class SubscriberConfig:
    imsi: str
    impi: str
    impu: str
    realm: str
    k: str
    opc: str


@dataclass(frozen=True)
class CallConfig:
    target_uri: str
    local_display_name: str
    user_agent: str = field(default_factory=lambda: f"DEMO-{uuid.uuid4()}")
    setup_timeout_seconds: float = 120.0


@dataclass(frozen=True)
class ImsConfig:
    register_expires: int = 600000
    compact_headers: bool = True
    initial_authorization: bool = True
    digest_res_encoding: str = "hex_lower"
    contact_transport: str = "tcp"
    contact_features: list[str] = field(default_factory=list)
    security_client_algorithms: list[str] = field(default_factory=lambda: ["hmac-md5-96", "hmac-sha-1-96"])
    security_client_encryption_algorithms: list[str] = field(
        default_factory=lambda: ["des-ede3-cbc", "aes-cbc", "null"]
    )


@dataclass(frozen=True)
class MediaConfig:
    codec: str
    payload_type: int
    clock_rate: int
    ptime_ms: int
    octet_align: bool
    send_file: str
    receive_file: str


@dataclass(frozen=True)
class DebugConfig:
    dump_sip: bool
    dump_sdp: bool
    dump_xfrm_commands: bool
    execute_xfrm_commands: bool
    capture_pcap: bool
    command_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class AppConfig:
    network: NetworkConfig
    subscriber: SubscriberConfig
    call: CallConfig
    ims: ImsConfig
    media: MediaConfig
    debug: DebugConfig
    base_dir: Path

    def summary_lines(self) -> list[str]:
        return [
            f"IMS interface: {self.network.interface}",
            f"P-CSCF: {self.network.pcscf_ip}:{self.network.pcscf_port}",
            f"Local SIP ports: clear={self.network.local_sip_port}, protected={self.network.local_protected_port}",
            f"Subscriber IMPI: {self.subscriber.impi}",
            f"Subscriber IMPU: {self.subscriber.impu}",
            f"Target URI: {self.call.target_uri}",
            f"REGISTER expires: {self.ims.register_expires}",
            f"Media: {self.media.codec} PT={self.media.payload_type} ptime={self.media.ptime_ms}ms",
            f"XFRM execution: {'enabled' if self.debug.execute_xfrm_commands else 'dry-run'}",
        ]


def load_config(path: str | Path, *, cli: dict[str, Any] | None = None) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a mapping")

    base_dir = config_path.parent.parent
    cli = cli or {}
    return AppConfig(
        network=_network_config(raw, cli),
        subscriber=_subscriber_config(cli),
        call=_call_config(raw, cli),
        ims=_optional_section(raw, "ims", ImsConfig),
        media=_section(raw, "media", MediaConfig),
        debug=_section(raw, "debug", DebugConfig),
        base_dir=base_dir,
    )


def _section(raw: dict[str, Any], name: str, cls: type) -> Any:
    value = raw.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"Missing config section: {name}")

    try:
        return cls(**value)
    except TypeError as exc:
        raise ConfigError(f"Invalid config section {name}: {exc}") from exc


def _optional_section(raw: dict[str, Any], name: str, cls: type) -> Any:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"Invalid config section {name}: expected mapping")

    try:
        return cls(**value)
    except TypeError as exc:
        raise ConfigError(f"Invalid config section {name}: {exc}") from exc


def _network_config(raw: dict[str, Any], cli: dict[str, Any]) -> NetworkConfig:
    network = raw.get("network", {})
    if not isinstance(network, dict):
        raise ConfigError("Invalid config section network: expected mapping")
    local_sip_port, local_protected_port, local_rtp_port = _random_local_ports()
    return NetworkConfig(
        interface=_required_cli(cli, "interface"),
        pcscf_ip=_required_cli(cli, "pcscf_ip"),
        pcscf_port=int(_required_cli(cli, "pcscf_port")),
        local_sip_port=local_sip_port,
        local_protected_port=local_protected_port,
        local_rtp_port=local_rtp_port,
        connect_timeout_seconds=network.get("connect_timeout_seconds", 5.0),
    )


def _subscriber_config(cli: dict[str, Any]) -> SubscriberConfig:
    return SubscriberConfig(
        imsi=_required_cli(cli, "imsi"),
        impi=_required_cli(cli, "impi"),
        impu=_required_cli(cli, "impu"),
        realm=_required_cli(cli, "realm"),
        k=_required_cli(cli, "k"),
        opc=_required_cli(cli, "opc"),
    )


def _call_config(raw: dict[str, Any], cli: dict[str, Any]) -> CallConfig:
    call = raw.get("call", {})
    if not isinstance(call, dict):
        raise ConfigError("Invalid config section call: expected mapping")
    return CallConfig(
        target_uri=_required_cli(cli, "target_uri"),
        local_display_name=call.get("local_display_name", "IMS Demo UE"),
        setup_timeout_seconds=call.get("setup_timeout_seconds", 120.0),
    )


def _required_cli(cli: dict[str, Any], name: str) -> Any:
    value = cli.get(name)
    if value is None or value == "":
        raise ConfigError(f"Missing required command-line argument: --{name.replace('_', '-')}")
    return value


def _random_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _random_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _random_local_ports() -> tuple[int, int, int]:
    while True:
        ports = (_random_tcp_port(), _random_tcp_port(), _random_udp_port())
        if len(set(ports)) == 3:
            return ports
