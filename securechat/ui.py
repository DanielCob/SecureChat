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


def _highlight_hex(data: bytes, highlight_idx: int | None, base_color_code: str) -> str:
    """Muestra hex resaltando en rojo brillante/subrayado el byte en highlight_idx."""
    if highlight_idx is None or not (0 <= highlight_idx < len(data)):
        return data.hex()
    if not _color:
        return data.hex()
    
    parts = []
    for idx, b in enumerate(data):
        b_hex = f"{b:02x}"
        if idx == highlight_idx:
            # Resaltar en rojo intenso subrayado o negrita y luego volver al color base
            parts.append(f"\033[1;31;4m{b_hex}\033[0m\033[{base_color_code}m")
        else:
            parts.append(b_hex)
    return "".join(parts)


def _parts(blob: bytes, base_color_code: str = _YELLOW, tampered_blob_idx: int | None = None) -> str:
    try:
        nonce, ct, tag = split_blob(blob)
    except ValueError:
        return _highlight_hex(blob, tampered_blob_idx, base_color_code)

    tampered_ct_idx = None
    if tampered_blob_idx is not None and len(nonce) <= tampered_blob_idx < len(nonce) + len(ct):
        tampered_ct_idx = tampered_blob_idx - len(nonce)

    blob_hex = _highlight_hex(blob, tampered_blob_idx, base_color_code)
    ct_hex = _highlight_hex(ct, tampered_ct_idx, base_color_code)

    return (f"{blob_hex}\n    nonce={nonce.hex()}\n    ciphertext={ct_hex}\n    tag={tag.hex()}")


def system(text: str) -> None:
    _emit(_GRAY, f"[*] {text}")


def local_plaintext(text: str) -> None:
    _emit(_GREEN, f"[TU] {text}")


def sent_ciphertext(blob: bytes, tampered_idx: int | None = None) -> None:
    _emit(_YELLOW, f"[ENVIADO ->] {_parts(blob, base_color_code=_YELLOW, tampered_blob_idx=tampered_idx)}")


def received_ciphertext(blob: bytes) -> None:
    _emit(_MAGENTA, f"[<- RECIBIDO] {_parts(blob, base_color_code=_MAGENTA)}")


def recovered_plaintext(peer_name: str, text: str) -> None:
    _emit(_CYAN, f"[{peer_name}] {text}")


def rejected(reason: str) -> None:
    _emit(_RED, f"[!] MENSAJE RECHAZADO: {reason}")
