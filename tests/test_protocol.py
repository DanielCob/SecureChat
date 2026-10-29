import socket

import pytest

from securechat import protocol


def test_frame_roundtrip_and_boundaries():
    a, b = socket.socketpair()
    protocol.send_frame(a, protocol.DATA, b"uno")
    protocol.send_frame(a, protocol.BYE)
    assert protocol.recv_frame(b) == (protocol.DATA, b"uno")
    assert protocol.recv_frame(b) == (protocol.BYE, b"")


def test_closed_peer_raises():
    a, b = socket.socketpair()
    a.close()
    with pytest.raises(protocol.ConnectionClosed):
        protocol.recv_frame(b)


def test_oversized_frame_rejected():
    a, b = socket.socketpair()
    a.sendall((protocol.MAX_PAYLOAD + 1).to_bytes(4, "big") + bytes([protocol.DATA]))
    with pytest.raises(protocol.ConnectionClosed):
        protocol.recv_frame(b)
