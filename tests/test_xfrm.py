from ipsec.security_header import SecurityAssociation
from ipsec.xfrm_manager import XfrmManager
from tools.command import CommandRunner


def test_xfrm_setup_commands_are_dry_run_safe():
    manager = XfrmManager(CommandRunner(execute=False))
    context = manager.build_context(
        ue_ip="10.0.0.1",
        pcscf_ip="10.0.0.2",
        local_clear_port=5060,
        local_protected_port=15060,
        local_security=SecurityAssociation(spi_c=1001, port_c=15060, port_s=5060),
        server_security=SecurityAssociation(spi_s=2002, port_c=15060, port_s=5060),
        ck_hex="00" * 16,
        ik_hex="11" * 16,
    )
    commands = manager.build_setup_commands(context)
    flattened = [" ".join(command) for command in commands]
    assert any("state add src 10.0.0.1 dst 10.0.0.2" in command for command in flattened)
    assert any("auth-trunc hmac(md5) 0x" in command for command in flattened)
    assert any("enc cipher_null 0x" in command for command in flattened)
    assert any("policy add dir out" in command for command in flattened)
