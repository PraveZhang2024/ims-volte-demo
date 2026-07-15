"""YAML configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    duration_seconds: int
    local_display_name: str
    user_agent: str = "python-ims-volte-demo/0.1"


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
            f"Media: {self.media.codec} PT={self.media.payload_type} ptime={self.media.ptime_ms}ms",
            f"XFRM execution: {'enabled' if self.debug.execute_xfrm_commands else 'dry-run'}",
        ]


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a mapping")

    base_dir = config_path.parent.parent
    return AppConfig(
        network=_section(raw, "network", NetworkConfig),
        subscriber=_section(raw, "subscriber", SubscriberConfig),
        call=_section(raw, "call", CallConfig),
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
