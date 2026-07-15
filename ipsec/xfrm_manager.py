"""Linux XFRM command generation for IMS 3GPP IPsec."""

from __future__ import annotations

from dataclasses import dataclass
import logging

from app.errors import IpsecError
from ipsec.security_header import SecurityAssociation
from tools.command import CommandRunner, CommandResult

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class XfrmContext:
    ue_ip: str
    pcscf_ip: str
    local_clear_port: int
    local_protected_port: int
    remote_port: int
    local_spi: int
    remote_spi: int
    ck_hex: str
    ik_hex: str
    auth_alg: str
    auth_trunc_bits: int
    enc_alg: str
    use_null_encryption: bool


class XfrmManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self._installed_contexts: list[XfrmContext] = []

    def build_context(
        self,
        *,
        ue_ip: str,
        pcscf_ip: str,
        local_clear_port: int,
        local_protected_port: int,
        local_security: SecurityAssociation,
        server_security: SecurityAssociation,
        ck_hex: str,
        ik_hex: str,
    ) -> XfrmContext:
        if not local_security.spi_c or not server_security.spi_s:
            raise IpsecError("Both local spi-c and server spi-s must be known")
        remote_port = server_security.port_s or 5060
        auth_alg, auth_trunc_bits = _linux_auth_alg(server_security.alg)
        enc_alg, use_null_encryption = _linux_enc_alg(server_security.ealg)
        return XfrmContext(
            ue_ip=ue_ip,
            pcscf_ip=pcscf_ip,
            local_clear_port=local_clear_port,
            local_protected_port=local_protected_port,
            remote_port=remote_port,
            local_spi=local_security.spi_c,
            remote_spi=server_security.spi_s,
            ck_hex=ck_hex,
            ik_hex=ik_hex,
            auth_alg=auth_alg,
            auth_trunc_bits=auth_trunc_bits,
            enc_alg=enc_alg,
            use_null_encryption=use_null_encryption,
        )

    def setup(self, context: XfrmContext) -> list[CommandResult]:
        commands = self.build_setup_commands(context)
        results = [self.runner.run(command) for command in commands]
        self._installed_contexts.append(context)
        return results

    def cleanup_all(self) -> list[CommandResult]:
        results: list[CommandResult] = []
        while self._installed_contexts:
            context = self._installed_contexts.pop()
            for command in self.build_cleanup_commands(context):
                LOGGER.info("Cleaning XFRM: %s", " ".join(command))
                result = self.runner.run(command, check=False)
                if result.returncode != 0:
                    LOGGER.warning("XFRM cleanup returned %s: %s", result.returncode, result.stderr.strip())
                results.append(result)
        return results

    def build_setup_commands(self, context: XfrmContext) -> list[list[str]]:
        return [
            self._state_add_out(context),
            self._state_add_in(context),
            self._policy_add_out(context),
            self._policy_add_in(context),
        ]

    def build_cleanup_commands(self, context: XfrmContext) -> list[list[str]]:
        return [
            ["ip", "xfrm", "policy", "delete", "dir", "out", "src", context.ue_ip, "dst", context.pcscf_ip],
            ["ip", "xfrm", "policy", "delete", "dir", "in", "src", context.pcscf_ip, "dst", context.ue_ip],
            ["ip", "xfrm", "state", "delete", "src", context.ue_ip, "dst", context.pcscf_ip, "proto", "esp", "spi", str(context.local_spi)],
            ["ip", "xfrm", "state", "delete", "src", context.pcscf_ip, "dst", context.ue_ip, "proto", "esp", "spi", str(context.remote_spi)],
        ]

    def check_commands(self) -> list[list[str]]:
        return [["ip", "-s", "xfrm", "state"], ["ip", "-s", "xfrm", "policy"]]

    def _state_add_out(self, context: XfrmContext) -> list[str]:
        command = [
            "ip",
            "xfrm",
            "state",
            "add",
            "src",
            context.ue_ip,
            "dst",
            context.pcscf_ip,
            "proto",
            "esp",
            "spi",
            str(context.local_spi),
            "mode",
            "transport",
            "auth-trunc",
            context.auth_alg,
            _hex_key(context.ik_hex),
            str(context.auth_trunc_bits),
        ]
        command.extend(_enc_args(context))
        return command

    def _state_add_in(self, context: XfrmContext) -> list[str]:
        command = [
            "ip",
            "xfrm",
            "state",
            "add",
            "src",
            context.pcscf_ip,
            "dst",
            context.ue_ip,
            "proto",
            "esp",
            "spi",
            str(context.remote_spi),
            "mode",
            "transport",
            "auth-trunc",
            context.auth_alg,
            _hex_key(context.ik_hex),
            str(context.auth_trunc_bits),
        ]
        command.extend(_enc_args(context))
        return command

    def _policy_add_out(self, context: XfrmContext) -> list[str]:
        return [
            "ip",
            "xfrm",
            "policy",
            "add",
            "dir",
            "out",
            "src",
            context.ue_ip,
            "dst",
            context.pcscf_ip,
            "proto",
            "tcp",
            "sport",
            str(context.local_protected_port),
            "dport",
            str(context.remote_port),
            "tmpl",
            "src",
            context.ue_ip,
            "dst",
            context.pcscf_ip,
            "proto",
            "esp",
            "mode",
            "transport",
        ]

    def _policy_add_in(self, context: XfrmContext) -> list[str]:
        return [
            "ip",
            "xfrm",
            "policy",
            "add",
            "dir",
            "in",
            "src",
            context.pcscf_ip,
            "dst",
            context.ue_ip,
            "proto",
            "tcp",
            "sport",
            str(context.remote_port),
            "dport",
            str(context.local_protected_port),
            "tmpl",
            "src",
            context.pcscf_ip,
            "dst",
            context.ue_ip,
            "proto",
            "esp",
            "mode",
            "transport",
        ]


def _linux_auth_alg(ims_alg: str) -> tuple[str, int]:
    normalized = ims_alg.lower()
    if normalized == "hmac-md5-96":
        return "hmac(md5)", 96
    if normalized in ("hmac-sha-1-96", "hmac-sha1-96"):
        return "hmac(sha1)", 96
    raise IpsecError(f"Unsupported IMS IPsec auth algorithm: {ims_alg}")


def _linux_enc_alg(ims_ealg: str) -> tuple[str, bool]:
    normalized = ims_ealg.lower()
    if normalized == "null":
        return "ecb(cipher_null)", True
    if normalized == "aes-cbc":
        return "cbc(aes)", False
    if normalized == "des-ede3-cbc":
        return "cbc(des3_ede)", False
    raise IpsecError(f"Unsupported IMS IPsec encryption algorithm: {ims_ealg}")


def _enc_args(context: XfrmContext) -> list[str]:
    if context.use_null_encryption:
        return ["enc", context.enc_alg, ""]
    return ["enc", context.enc_alg, _hex_key(context.ck_hex)]


def _hex_key(value: str) -> str:
    return value if value.startswith("0x") else f"0x{value}"
