"""Paso 5 - Interfaz de consola. RESPONSABLE: Integrante A.

Funciones de salida con colores ANSI (distincion visual exigida por el enunciado).
Todas imprimen bajo un Lock comun para que el hilo receptor no mezcle lineas con lo que
el usuario esta escribiendo.

    system     -> gris     [*] eventos (conexion, handshake, huellas)
    local      -> verde    [TU] plaintext que escribiste
    sent_ct    -> amarillo [ENVIADO ->] ciphertext en hex (nonce | ct | tag)
    recv_ct    -> magenta  [<- RECIBIDO] ciphertext en hex tal como llego del socket
    recovered  -> cian     [NOMBRE] plaintext recuperado SOLO tras verificar el tag
    rejected   -> rojo     [!] mensaje rechazado: autenticacion fallida (sin plaintext)
"""
import os
import sys
import threading

from .session_crypto import split_blob

PROMPT = "> "
_lock = threading.Lock()
prompt_enabled = False  # chat.run_chat lo activa; antes del chat no se dibuja prompt
_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_GRAY, _GREEN, _YELLOW, _MAGENTA, _CYAN, _RED = "90", "32", "33", "35", "36", "31"


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _color else text


def _emit(code: str, text: str) -> None:
    with _lock:
        # \r\033[K borra el prompt a medio escribir; luego lo redibujamos.
        if _color and prompt_enabled:
            sys.stdout.write("\r\033[K")
        sys.stdout.write(_paint(code, text) + "\n")
        if prompt_enabled:
            sys.stdout.write(PROMPT)
        sys.stdout.flush()


def reprompt() -> None:
    with _lock:
        sys.stdout.write(PROMPT)
        sys.stdout.flush()


def _parts(blob: bytes) -> str:
    try:
        nonce, ct, tag = split_blob(blob)
    except ValueError:
        return blob.hex()
    return (f"{blob.hex()}\n    nonce={nonce.hex()}\n    ciphertext={ct.hex()}\n    tag={tag.hex()}")


def system(text: str) -> None:
    _emit(_GRAY, f"[*] {text}")


def local_plaintext(text: str) -> None:
    _emit(_GREEN, f"[TU] {text}")


def sent_ciphertext(blob: bytes) -> None:
    _emit(_YELLOW, f"[ENVIADO ->] {_parts(blob)}")


def received_ciphertext(blob: bytes) -> None:
    _emit(_MAGENTA, f"[<- RECIBIDO] {_parts(blob)}")


def recovered_plaintext(peer_name: str, text: str) -> None:
    _emit(_CYAN, f"[{peer_name}] {text}")


def rejected(reason: str) -> None:
    _emit(_RED, f"[!] MENSAJE RECHAZADO: {reason}")
