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

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import protocol
from .keys import fingerprint, public_key_from_pem, public_key_to_pem
from .session_crypto import InvalidMessage, SessionCipher, generate_session_key


class HandshakeError(Exception):
    """Frame inesperado, cierre prematuro, RSA/OAEP invalido o READY incorrecto."""


@dataclass
class HandshakeResult:
    cipher: SessionCipher          # ya listo para encrypt/decrypt
    peer_name: str
    peer_fingerprint: str          # keys.fingerprint(clave publica del par)
    wrapped_key: bytes             # blob RSA que cruzo el socket (A lo muestra como evidencia)


def _get_oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_session_key(peer_public: RSAPublicKey, session_key: bytes) -> bytes:
    """RSA-OAEP(SHA-256). B."""
    try:
        return peer_public.encrypt(session_key, _get_oaep_padding())
    except Exception as e:
        raise HandshakeError(f"Error encapsulando la clave de sesion: {e}") from e


def unwrap_session_key(private_key: RSAPrivateKey, wrapped: bytes) -> bytes:
    """Inverso de wrap_session_key. Lanza HandshakeError si falla. B."""
    try:
        return private_key.decrypt(wrapped, _get_oaep_padding())
    except Exception as e:
        raise HandshakeError(f"Fallo al descifrar clave de sesion con RSA-OAEP: {e}") from e


def perform_handshake(sock: socket.socket, my_name: str, private_key: RSAPrivateKey,
                      is_initiator: bool) -> HandshakeResult:
    """Ejecuta el handshake sobre un socket ya conectado y devuelve el resultado.
    B escribe el cuerpo; A lo llama desde __main__ y muestra los mensajes de estado
    (ui.system) antes/despues. Debe probarse con socket.socketpair() (tests/test_handshake.py)."""
    try:
        my_pub_pem = public_key_to_pem(private_key.public_key())
        my_name_bytes = my_name.encode("utf-8")

        if is_initiator:
            # 1. Enviar HELLO(nombre) y recibir HELLO(nombre)
            protocol.send_frame(sock, protocol.HELLO, my_name_bytes)
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.HELLO:
                raise HandshakeError(f"Esperado frame HELLO, recibido {ftype:#x}")
            peer_name = payload.decode("utf-8", errors="replace")

            # 2. Enviar PUBKEY y recibir PUBKEY
            protocol.send_frame(sock, protocol.PUBKEY, my_pub_pem)
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.PUBKEY:
                raise HandshakeError(f"Esperado frame PUBKEY, recibido {ftype:#x}")
            try:
                peer_pub = public_key_from_pem(payload)
            except ValueError as e:
                raise HandshakeError(f"Clave publica del par invalida: {e}") from e

            # 3. Generar clave de sesion y enviarla cifrada con RSA-OAEP
            session_key = generate_session_key()
            wrapped_key = wrap_session_key(peer_pub, session_key)
            protocol.send_frame(sock, protocol.SESSION_KEY, wrapped_key)

            # 4. Crear cipher local y esperar confirmacion READY
            cipher = SessionCipher(session_key, is_initiator=True)
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.READY:
                raise HandshakeError(f"Esperado frame READY, recibido {ftype:#x}")

            try:
                ready_pt = cipher.decrypt(payload)
            except InvalidMessage as e:
                raise HandshakeError(f"Fallo de autenticacion del frame READY: {e}") from e

            if ready_pt != b"READY":
                raise HandshakeError(f"Contenido de READY inesperado: {ready_pt!r}")

        else:
            # RESPONDEDOR
            # 1. Recibir HELLO(nombre) y enviar HELLO(nombre)
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.HELLO:
                raise HandshakeError(f"Esperado frame HELLO, recibido {ftype:#x}")
            peer_name = payload.decode("utf-8", errors="replace")
            protocol.send_frame(sock, protocol.HELLO, my_name_bytes)

            # 2. Recibir PUBKEY y enviar PUBKEY
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.PUBKEY:
                raise HandshakeError(f"Esperado frame PUBKEY, recibido {ftype:#x}")
            try:
                peer_pub = public_key_from_pem(payload)
            except ValueError as e:
                raise HandshakeError(f"Clave publica del par invalida: {e}") from e
            protocol.send_frame(sock, protocol.PUBKEY, my_pub_pem)

            # 3. Recibir SESSION_KEY y descifrar con privada
            ftype, payload = protocol.recv_frame(sock)
            if ftype != protocol.SESSION_KEY:
                raise HandshakeError(f"Esperado frame SESSION_KEY, recibido {ftype:#x}")
            wrapped_key = payload
            session_key = unwrap_session_key(private_key, wrapped_key)

            # 4. Crear cipher, cifrar b"READY" y enviar frame READY
            cipher = SessionCipher(session_key, is_initiator=False)
            ready_payload = cipher.encrypt(b"READY")
            protocol.send_frame(sock, protocol.READY, ready_payload)

        peer_fp = fingerprint(peer_pub)
        return HandshakeResult(
            cipher=cipher,
            peer_name=peer_name,
            peer_fingerprint=peer_fp,
            wrapped_key=wrapped_key,
        )

    except protocol.ConnectionClosed as e:
        raise HandshakeError(f"Conexion cerrada durante handshake: {e}") from e
