from sip.dialog import SipDialog
from sip.parser import parse_sip_message


def test_dialog_remote_target_uses_contact_uri_without_name_addr_wrapper():
    response = parse_sip_message(
        "SIP/2.0 180 Ringing\r\n"
        "To: <sip:b@example.com>;tag=remote\r\n"
        "Contact: <sip:uas-dlg--abc@10.2.30.160:5060>\r\n"
        "Record-Route: <sip:mo@10.2.30.160:5060;lr>\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    dialog = SipDialog(call_id="call", local_tag="local")
    dialog.update_from_response(response)
    assert dialog.remote_target == "sip:uas-dlg--abc@10.2.30.160:5060"
    assert dialog.request_uri("sip:fallback@example.com") == "sip:uas-dlg--abc@10.2.30.160:5060"
