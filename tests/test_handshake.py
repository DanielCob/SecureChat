import socket
import threading

import pytest

from securechat import handshake, keys, protocol


@pytest.fixture(scope="module")
def alice_bob_keys():
    return keys.generate_keypair(), keys.generate_keypair()


def _run(sa, sb, ka, kb):
    out = {}

    def side(name, sock, key, init):
        try:
            out[name] = handshake.perform_handshake(sock, name, key, init)
        except Exception as e:  # noqa: BLE001
            out[name] = e

    ts = [threading.Thread(target=side, args=("Alice", sa, ka, True)),
          threading.Thread(target=side, args=("Bob", sb, kb, False))]
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    return out


def test_handshake_yields_compatible_ciphers(alice_bob_keys):
    ka, kb = alice_bob_keys
    sa, sb = socket.socketpair()
    out = _run(sa, sb, ka, kb)
    a, b = out["Alice"], out["Bob"]
    assert a.peer_name == "Bob" and b.peer_name == "Alice"
    assert a.peer_fingerprint == keys.fingerprint(kb.public_key())
    assert b.cipher.decrypt(a.cipher.encrypt(b"hola")) == b"hola"
    assert a.cipher.decrypt(b.cipher.encrypt(b"hey")) == b"hey"


def test_wrap_unwrap_roundtrip_and_not_plaintext(alice_bob_keys):
    _, kb = alice_bob_keys
    sk = b"\x07" * 32
    wrapped = handshake.wrap_session_key(kb.public_key(), sk)
    assert sk not in wrapped
    assert handshake.unwrap_session_key(kb, wrapped) == sk
    assert handshake.wrap_session_key(kb.public_key(), sk) != wrapped  # OAEP es aleatorio


def test_unwrap_with_wrong_key_fails(alice_bob_keys):
    ka, kb = alice_bob_keys
    wrapped = handshake.wrap_session_key(kb.public_key(), b"\x01" * 32)
    with pytest.raises(handshake.HandshakeError):
        handshake.unwrap_session_key(ka, wrapped)


def test_session_key_and_private_key_never_on_the_wire(alice_bob_keys):
    """Sniffer en el medio: reenvia todo y guarda los bytes."""
    ka, kb = alice_bob_keys
    a_end, mid_a = socket.socketpair()
    mid_b, b_end = socket.socketpair()
    seen = bytearray()

    def pump(src, dst):
        try:
            while (d := src.recv(4096)):
                seen.extend(d)
                dst.sendall(d)
        except OSError:
            pass

    for s, d in ((mid_a, mid_b), (mid_b, mid_a)):
        threading.Thread(target=pump, args=(s, d), daemon=True).start()
    out = _run(a_end, b_end, ka, kb)
    assert not isinstance(out["Alice"], Exception), out["Alice"]
    # La clave de sesion real no puede aparecer en claro; probamos con un blob cifrado de prueba:
    probe = out["Alice"].cipher.encrypt(b"p")
    assert probe not in seen
    d_bytes = ka.private_numbers().d.to_bytes(256, "big")
    assert d_bytes not in seen and b"PRIVATE KEY" not in seen


def test_garbage_frame_raises_handshake_error(alice_bob_keys):
    _, kb = alice_bob_keys
    a, b = socket.socketpair()
    protocol.send_frame(a, protocol.DATA, b"no deberia estar aqui")
    with pytest.raises(handshake.HandshakeError):
        handshake.perform_handshake(b, "Bob", kb, is_initiator=False)
