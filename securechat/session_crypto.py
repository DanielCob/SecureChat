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

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32


class InvalidMessage(Exception):
    """Tag invalido, blob mal formado, clave incorrecta o nonce repetido/fuera de orden.
    El llamador (A) NUNCA debe mostrar plaintext si se lanza esto."""


def generate_session_key() -> bytes:
    """32 bytes aleatorios del CSPRNG del SO (os.urandom / AESGCM.generate_key(256))."""
    # TODO(B)
    raise NotImplementedError


def split_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """(nonce, ciphertext, tag). Lo usa la UI de A para mostrar cada parte. ValueError si es corto."""
    # TODO(B)
    raise NotImplementedError


class SessionCipher:
    """Estado de una sesion: clave + contadores. Una instancia por extremo."""

    def __init__(self, key: bytes, is_initiator: bool):
        """key de 32 bytes (ValueError si no). is_initiator decide la direccion de envio."""
        # TODO(B)
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Devuelve el blob nonce||ciphertext||tag. Avanza el contador de envio."""
        # TODO(B)
        raise NotImplementedError

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Verifica tag + nonce ANTES de devolver plaintext. Lanza InvalidMessage si falla
        (envolver InvalidTag de cryptography). Solo avanza el contador de recepcion si es valido."""
        # TODO(B)
        raise NotImplementedError
