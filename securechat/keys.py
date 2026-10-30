"""Paso 2 - Criptografia asimetrica (RSA). RESPONSABLE: Integrante B.

Biblioteca: `cryptography` (hazmat.primitives.asymmetric.rsa / serialization).
Requisitos del enunciado: RSA >= 2048 bits; la clave privada nunca viaja por el
socket y nunca se imprime completa.
"""
import os
import stat
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

KEY_BITS = 2048


def generate_keypair(bits: int = KEY_BITS) -> RSAPrivateKey:
    """Genera un par RSA (public_exponent=65537). Rechazar bits < 2048 con ValueError."""
    if bits < 2048:
        raise ValueError(f"El tamaño de clave debe ser de al menos 2048 bits (solicitado: {bits})")
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )


def save_private_key(key: RSAPrivateKey, path: str, password: bytes | None = None) -> None:
    """Guarda en PEM PKCS8. Crear el archivo con permisos 0o600 (solo el dueno).
    Si password no es None, cifrar con BestAvailableEncryption."""
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    pem_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    # Crear directorio padre si no existe
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    # Usar os.open con flags y modo 0o600 para asegurar permisos estrictos desde la creación
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(path, flags, mode)
    with open(fd, "wb") as f:
        f.write(pem_data)
    # Por si la umask modificó los permisos, aseguramos explícitamente 0o600
    os.chmod(path, mode)


def load_private_key(path: str, password: bytes | None = None) -> RSAPrivateKey:
    """Carga una clave privada en formato PEM PKCS8 desde path."""
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("La clave privada cargada no es RSA")
    return key


def load_or_create_keypair(path: str, password: bytes | None = None) -> RSAPrivateKey:
    """Si `path` existe, la carga; si no, genera y guarda. Lo usa __main__ (A)."""
    if os.path.exists(path):
        return load_private_key(path, password=password)
    key = generate_keypair()
    save_private_key(key, path, password=password)
    return key


def public_key_to_pem(pub: RSAPublicKey) -> bytes:
    """PEM SubjectPublicKeyInfo. Es lo que viaja en el frame PUBKEY."""
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(data: bytes) -> RSAPublicKey:
    """Debe lanzar ValueError si no es RSA o si es < 2048 bits."""
    try:
        pub = serialization.load_pem_public_key(data)
    except Exception as e:
        raise ValueError(f"No se pudo cargar la clave pública: {e}") from e

    if not isinstance(pub, RSAPublicKey):
        raise ValueError("La clave pública recibida no es de tipo RSA")
    if pub.key_size < 2048:
        raise ValueError(f"Clave pública insegura: {pub.key_size} bits (mínimo 2048 requerido)")
    return pub


def fingerprint(pub: RSAPublicKey) -> str:
    """SHA-256 del DER SubjectPublicKeyInfo, en hex agrupado 'ab:cd:...' (primeros 16 bytes
    bastan). A lo muestra en pantalla para que los dos comparen que no hay intermediario."""
    der_bytes = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_bytes)
    h = digest.finalize()
    first_16 = h[:16]
    return ":".join(f"{b:02x}" for b in first_16)


def describe_private_key(key: RSAPrivateKey) -> str:
    """Resumen SEGURO para la UI, p. ej. 'RSA-2048 (privada: oculta)'. Nunca el PEM/numeros."""
    return f"RSA-{key.key_size} (privada: oculta/protegida)"
