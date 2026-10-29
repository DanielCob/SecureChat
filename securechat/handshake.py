"""Paso 3 - Handshake. RESPONSABLES: B (logica criptografica) y A (conexion/integracion).

Flujo (los dos roles usan los frames de protocol.py):

    INICIADOR (el que hace `connect`)             RESPONDEDOR (el que hace `listen`)
    ---------------------------------             ----------------------------------
    HELLO(nombre)             ------------------>
                              <------------------ HELLO(nombre)
    PUBKEY(pem propia)        ------------------>
                              <------------------ PUBKEY(pem propia)
    key = generate_session_key()
    SESSION_KEY(RSA-OAEP(pub_resp, key)) ------->  key = RSA-OAEP-decrypt(priv_resp, ...)
                              <------------------ READY(cipher.encrypt(b"READY"))
    cipher.decrypt(READY) == b"READY"  => sesion establecida en ambos extremos

Reglas: RSA-OAEP con MGF1(SHA-256) y SHA-256, label=None. La clave de sesion jamas viaja
en claro ni se escribe en el codigo. READY demuestra que ambos tienen la misma clave
(si el descifrado falla -> HandshakeError).
Limitacion conocida (mencionar en el README): las claves publicas no estan autenticadas;
por eso A muestra la huella (keys.fingerprint) para compararla a mano.
"""
import socket
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .session_crypto import SessionCipher


class HandshakeError(Exception):
    """Frame inesperado, cierre prematuro, RSA/OAEP invalido o READY incorrecto."""


@dataclass
class HandshakeResult:
    cipher: SessionCipher          # ya listo para encrypt/decrypt
    peer_name: str
    peer_fingerprint: str          # keys.fingerprint(clave publica del par)
    wrapped_key: bytes             # blob RSA que cruzo el socket (A lo muestra como evidencia)


def wrap_session_key(peer_public: RSAPublicKey, session_key: bytes) -> bytes:
    """RSA-OAEP(SHA-256). B."""
    # TODO(B)
    raise NotImplementedError


def unwrap_session_key(private_key: RSAPrivateKey, wrapped: bytes) -> bytes:
    """Inverso de wrap_session_key. Lanza HandshakeError si falla. B."""
    # TODO(B)
    raise NotImplementedError


def perform_handshake(sock: socket.socket, my_name: str, private_key: RSAPrivateKey,
                      is_initiator: bool) -> HandshakeResult:
    """Ejecuta el diagrama de arriba sobre un socket ya conectado y devuelve el resultado.
    B escribe el cuerpo; A lo llama desde __main__ y muestra los mensajes de estado
    (ui.system) antes/despues. Debe probarse con socket.socketpair() (tests/test_handshake.py)."""
    # TODO(B)
    raise NotImplementedError
