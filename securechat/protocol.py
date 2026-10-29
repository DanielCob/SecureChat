"""Formato de cable compartido (contrato A <-> B). YA IMPLEMENTADO: no cambiar sin avisar.

Cada mensaje en el socket es un *frame*:

    +----------------+----------+------------------+
    | longitud (4 B) | tipo (1) | payload (N bytes)|
    +----------------+----------+------------------+
      big-endian, = N

TCP es un flujo de bytes sin fronteras de mensaje; el frame las restaura.
Funciona sobre cualquier socket, incluido socket.socketpair() (util para tests).
"""
import socket
import struct

# Tipos de frame
HELLO = 0x01        # payload: nombre del participante (utf-8)
PUBKEY = 0x02       # payload: clave publica RSA en PEM (SubjectPublicKeyInfo)
SESSION_KEY = 0x03  # payload: clave de sesion cifrada con RSA-OAEP (iniciador -> respondedor)
READY = 0x04        # payload: blob AES-GCM (ver session_crypto) que confirma la sesion
DATA = 0x05         # payload: blob AES-GCM = nonce(12) || ciphertext || tag(16)
BYE = 0x06          # payload: vacio; cierre ordenado

MAX_PAYLOAD = 64 * 1024
_HEADER = struct.Struct(">IB")


class ConnectionClosed(Exception):
    """El par cerro la conexion (o llego un frame invalido)."""


def send_frame(sock: socket.socket, ftype: int, payload: bytes = b"") -> None:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload demasiado grande")
    sock.sendall(_HEADER.pack(len(payload), ftype) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionClosed("conexion cerrada por el par")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Bloquea hasta recibir un frame completo. Devuelve (tipo, payload)."""
    length, ftype = _HEADER.unpack(_recv_exact(sock, _HEADER.size))
    if length > MAX_PAYLOAD:
        raise ConnectionClosed(f"frame demasiado grande ({length} bytes)")
    return ftype, _recv_exact(sock, length)
