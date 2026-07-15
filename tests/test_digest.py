from aka.digest_akav1 import DigestCredentials, build_authorization, calculate_response


def test_digest_authorization_contains_expected_fields():
    credentials = DigestCredentials(
        username="001@ims",
        realm="ims",
        uri="sip:ims",
        method="REGISTER",
        res_hex="01020304",
        nonce="nonce",
        qop="auth",
        opaque="opaque",
        cnonce="cnonce",
    )
    header = build_authorization(credentials)
    assert header.startswith("Digest ")
    assert 'username="001@ims"' in header
    assert "algorithm=AKAv1-MD5" in header
    assert f'response="{calculate_response(credentials)}"' in header
