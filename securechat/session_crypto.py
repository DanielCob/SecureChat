"""Paso 4 - Cifrado simetrico autenticado AES-256-GCM. RESPONSABLE: Integrante B.

Formato del blob que viaja en DATA/READY:   nonce(12) || ciphertext || tag(16)
(`AESGCM.encrypt` de la libreria `cryptography` ya devuelve ciphertext||tag.)

Politica de nonce (obligatoria, es "manejo estricto de nonces" del enunciado):
    nonce = direccion(4 B, big-endian) || contador(8 B, big-endian)
    direccion: 1 = iniciador -> respondedor, 2 = respondedor -> iniciador
    - El emisor incrementa su contador en cada cifrado (nunca repite bajo la misma clave).
    - El receptor exige direccion == la del par y contador ESTRICTAMENTE mayor que el
      ultimo aceptado (rechaza repeticion/reordenamiento: InvalidMessage).
    - Mantener el contador fuera de rango (>= 2**64) -> error.
La direccion evita que Alice y Bob reutilicen el mismo nonce con la misma clave.
"""
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32


class InvalidMessage(Exception):
    """Tag invalido, blob mal formado, clave incorrecta o nonce repetido/fuera de orden.
    El llamador (A) NUNCA debe mostrar plaintext si se lanza esto."""


def generate_session_key() -> bytes:
    """32 bytes aleatorios del CSPRNG del SO (os.urandom / AESGCM.generate_key(256))."""
    return os.urandom(KEY_LEN)


def split_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """(nonce, ciphertext, tag). Lo usa la UI de A para mostrar cada parte. ValueError si es corto."""
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError(f"Blob demasiado corto ({len(blob)} bytes), minimo esperado {NONCE_LEN + TAG_LEN}")
    nonce = blob[:NONCE_LEN]
    ciphertext = blob[NONCE_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]
    return nonce, ciphertext, tag


class SessionCipher:
    """Estado de una sesion: clave + contadores. Una instancia por extremo."""

    def __init__(self, key: bytes, is_initiator: bool):
        """key de 32 bytes (ValueError si no). is_initiator decide la direccion de envio."""
        if len(key) != KEY_LEN:
            raise ValueError(f"Clave de sesion invalida: esperados {KEY_LEN} bytes, recibidos {len(key)}")
        self._key = key
        self._is_initiator = is_initiator
        self._aesgcm = AESGCM(self._key)

        # Direcciones: 1 = iniciador -> respondedor, 2 = respondedor -> iniciador
        self._send_dir = 1 if is_initiator else 2
        self._recv_dir = 2 if is_initiator else 1

        self._send_counter = 0
        self._last_recv_counter = 0

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Devuelve el blob nonce||ciphertext||tag. Avanza el contador de envio."""
        self._send_counter += 1
        if self._send_counter >= (1 << 64):
            raise OverflowError("Contador de nonce agotado (>= 2^64)")

        nonce = struct.pack(">IQ", self._send_dir, self._send_counter)
        ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct_and_tag

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Verifica tag + nonce ANTES de devolver plaintext. Lanza InvalidMessage si falla
        (envolver InvalidTag de cryptography). Solo avanza el contador de recepcion si es valido."""
        if len(blob) < NONCE_LEN + TAG_LEN:
            raise InvalidMessage("Blob truncado o mas corto que nonce + tag")

        nonce = blob[:NONCE_LEN]
        ct_and_tag = blob[NONCE_LEN:]

        try:
            direction, counter = struct.unpack(">IQ", nonce)
        except struct.error as e:
            raise InvalidMessage("Formato de nonce invalido") from e

        if direction != self._recv_dir:
            raise InvalidMessage(f"Direccion de nonce inesperada: esperada {self._recv_dir}, recibida {direction}")

        if counter <= self._last_recv_counter:
            raise InvalidMessage(f"Replay o reordenamiento: contador {counter} <= ultimo {self._last_recv_counter}")

        try:
            plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, aad)
        except InvalidTag as e:
            raise InvalidMessage("Fallo de autenticacion (tag invalido o datos alterados)") from e
        except Exception as e:
            raise InvalidMessage(f"Error al descifrar: {e}") from e

        # Solo avanzamos el contador si todo fue verificado con exito
        self._last_recv_counter = counter
        return plaintext
