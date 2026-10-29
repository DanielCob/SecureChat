"""Paso 5 - Interfaz de consola. RESPONSABLE: Integrante A.

Funciones de salida con colores ANSI (distincion visual exigida por el enunciado).
Todas las que imprimen desde el hilo receptor deben usar un Lock comun para no mezclar
lineas con lo que el usuario esta escribiendo.

Convencion de colores sugerida:
    system     -> gris     [*] eventos (conexion, handshake, huellas)
    local      -> verde    [TU] plaintext que escribiste
    sent_ct    -> amarillo [ENVIADO  ->] ciphertext en hex (nonce | ct | tag separados)
    recv_ct    -> magenta  [<- RECIBIDO] ciphertext en hex tal como llego del socket
    recovered  -> cian     [NOMBRE] plaintext recuperado SOLO tras verificar el tag
    rejected   -> rojo     [!] mensaje rechazado: autenticacion fallida (sin plaintext)
"""


def system(text: str) -> None:
    # TODO(A)
    raise NotImplementedError


def local_plaintext(text: str) -> None:
    # TODO(A)
    raise NotImplementedError


def sent_ciphertext(blob: bytes) -> None:
    """Mostrar el blob en hex y, por claridad, desglosado: nonce | ciphertext | tag
    (usar session_crypto.split_blob)."""
    # TODO(A)
    raise NotImplementedError


def received_ciphertext(blob: bytes) -> None:
    # TODO(A)
    raise NotImplementedError


def recovered_plaintext(peer_name: str, text: str) -> None:
    # TODO(A)
    raise NotImplementedError


def rejected(reason: str) -> None:
    # TODO(A)
    raise NotImplementedError
