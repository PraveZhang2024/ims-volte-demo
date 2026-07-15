import base64

from aka.milenage_service import AkaChallenge


def test_aka_nonce_splits_rand_and_autn():
    rand = bytes(range(16))
    autn = bytes(range(16, 32))
    nonce = base64.b64encode(rand + autn).decode()
    challenge = AkaChallenge.from_nonce(nonce)
    assert challenge.rand == rand
    assert challenge.autn == autn
    assert challenge.sqn_xor_ak == autn[:6]
    assert challenge.amf == autn[6:8]
    assert challenge.mac_a == autn[8:16]
