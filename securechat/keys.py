"""Paso 2 - Criptografia asimetrica (RSA). RESPONSABLE: Integrante B.

Biblioteca: `cryptography` (hazmat.primitives.asymmetric.rsa / serialization).
Requisitos del enunciado: RSA >= 2048 bits; la clave privada nunca viaja por el
socket y nunca se imprime completa.
"""
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

KEY_BITS = 2048


def generate_keypair(bits: int = KEY_BITS) -> RSAPrivateKey:
    """Genera un par RSA (public_exponent=65537). Rechazar bits < 2048 con ValueError."""
    # TODO(B)
    raise NotImplementedError


def save_private_key(key: RSAPrivateKey, path: str, password: bytes | None = None) -> None:
    """Guarda en PEM PKCS8. Crear el archivo con permisos 0o600 (solo el dueno).
    Si password no es None, cifrar con BestAvailableEncryption."""
    # TODO(B)
    raise NotImplementedError


def load_private_key(path: str, password: bytes | None = None) -> RSAPrivateKey:
    # TODO(B)
    raise NotImplementedError


def load_or_create_keypair(path: str, password: bytes | None = None) -> RSAPrivateKey:
    """Si `path` existe, la carga; si no, genera y guarda. Lo usa __main__ (A)."""
    # TODO(B)
    raise NotImplementedError


def public_key_to_pem(pub: RSAPublicKey) -> bytes:
    """PEM SubjectPublicKeyInfo. Es lo que viaja en el frame PUBKEY."""
    # TODO(B)
    raise NotImplementedError


def public_key_from_pem(data: bytes) -> RSAPublicKey:
    """Debe lanzar ValueError si no es RSA o si es < 2048 bits."""
    # TODO(B)
    raise NotImplementedError


def fingerprint(pub: RSAPublicKey) -> str:
    """SHA-256 del DER SubjectPublicKeyInfo, en hex agrupado 'ab:cd:...' (primeros 16 bytes
    bastan). A lo muestra en pantalla para que los dos comparen que no hay intermediario."""
    # TODO(B)
    raise NotImplementedError


def describe_private_key(key: RSAPrivateKey) -> str:
    """Resumen SEGURO para la UI, p. ej. 'RSA-2048 (privada: oculta)'. Nunca el PEM/numeros."""
    # TODO(B)
    raise NotImplementedError
