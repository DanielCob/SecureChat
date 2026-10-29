import pytest

from securechat.session_crypto import (InvalidMessage, NONCE_LEN, SessionCipher, TAG_LEN,
                                       generate_session_key, split_blob)


@pytest.fixture
def pair():
    k = generate_session_key()
    return SessionCipher(k, is_initiator=True), SessionCipher(k, is_initiator=False)


def test_key_is_32_random_bytes():
    assert len(generate_session_key()) == 32
    assert generate_session_key() != generate_session_key()


def test_roundtrip_both_directions(pair):
    a, b = pair
    assert b.decrypt(a.encrypt(b"hola bob")) == b"hola bob"
    assert a.decrypt(b.encrypt(b"hola alice")) == b"hola alice"


def test_blob_layout_and_no_plaintext(pair):
    a, _ = pair
    pt = b"mensaje secreto"
    blob = a.encrypt(pt)
    assert len(blob) == NONCE_LEN + len(pt) + TAG_LEN
    assert pt not in blob
    nonce, ct, tag = split_blob(blob)
    assert (len(nonce), len(ct), len(tag)) == (NONCE_LEN, len(pt), TAG_LEN)


def test_nonces_never_repeat(pair):
    a, _ = pair
    nonces = {split_blob(a.encrypt(b"x"))[0] for _ in range(2000)}
    assert len(nonces) == 2000


def test_each_direction_uses_different_nonce_space():
    k = generate_session_key()
    a, b = SessionCipher(k, True), SessionCipher(k, False)
    assert split_blob(a.encrypt(b"x"))[0] != split_blob(b.encrypt(b"x"))[0]


def test_flip_each_byte_fresh_receiver():
    k = generate_session_key()
    blob = SessionCipher(k, True).encrypt(b"integridad")
    for i in range(len(blob)):
        bad = bytearray(blob)
        bad[i] ^= 0x01
        with pytest.raises(InvalidMessage):
            SessionCipher(k, False).decrypt(bytes(bad))


def test_wrong_key_rejected():
    blob = SessionCipher(generate_session_key(), True).encrypt(b"x")
    with pytest.raises(InvalidMessage):
        SessionCipher(generate_session_key(), False).decrypt(blob)


def test_truncated_blob_rejected(pair):
    _, b = pair
    with pytest.raises(InvalidMessage):
        b.decrypt(b"corto")


def test_replay_and_reorder_rejected(pair):
    a, b = pair
    m1, m2 = a.encrypt(b"1"), a.encrypt(b"2")
    assert b.decrypt(m2) == b"2"
    with pytest.raises(InvalidMessage):
        b.decrypt(m2)  # repeticion
    with pytest.raises(InvalidMessage):
        b.decrypt(m1)  # fuera de orden


def test_failed_decrypt_does_not_advance_state(pair):
    a, b = pair
    good = a.encrypt(b"ok")
    bad = bytearray(good)
    bad[-1] ^= 1
    with pytest.raises(InvalidMessage):
        b.decrypt(bytes(bad))
    assert b.decrypt(good) == b"ok"


def test_reflected_own_message_rejected(pair):
    a, _ = pair
    with pytest.raises(InvalidMessage):
        a.decrypt(a.encrypt(b"eco"))  # direccion equivocada
