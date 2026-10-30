"""Pasos 1, 5 y 6 - Bucle de chat concurrente. RESPONSABLE: Integrante A.

Hilo receptor (daemon): lee frames; DATA -> verifica/descifra; BYE o cierre -> termina.
Hilo principal: lee el teclado y es el unico que envia.
  texto normal  -> cifra y envia
  /tamper <t>   -> Paso 6: cifra, voltea 1 byte del ciphertext y envia (el par debe rechazarlo)
  /quit         -> BYE y cierre ordenado
"""
import _thread
import socket
import threading

from . import protocol, ui
from .session_crypto import NONCE_LEN, InvalidMessage, SessionCipher

HELP = "comandos: /quit  /tamper <texto>  /help"


def _receiver(sock: socket.socket, cipher: SessionCipher, peer_name: str,
              closing: threading.Event) -> None:
    try:
        while True:
            ftype, payload = protocol.recv_frame(sock)
            if ftype == protocol.BYE:
                ui.system(f"{peer_name} cerró la sesión")
                break
            if ftype != protocol.DATA:
                ui.rejected(f"frame inesperado (tipo {ftype}) ignorado")
                continue
            ui.received_ciphertext(payload)
            try:
                plaintext = cipher.decrypt(payload)
            except InvalidMessage as e:
                ui.rejected(f"autenticación fallida, el contenido se descarta ({e})")
                continue
            ui.recovered_plaintext(peer_name, plaintext.decode("utf-8", errors="replace"))
    except (protocol.ConnectionClosed, OSError):
        if not closing.is_set():
            ui.system(f"conexión con {peer_name} perdida")
    if not closing.is_set():
        closing.set()
        _thread.interrupt_main()  # saca al hilo principal de input()


def _send(sock: socket.socket, cipher: SessionCipher, text: str, tamper: bool = False) -> None:
    ui.local_plaintext(text)
    blob = cipher.encrypt(text.encode("utf-8"))
    tampered_idx = None
    if tamper:
        i = NONCE_LEN  # primer byte del ciphertext
        original_byte = blob[i]
        tampered_byte = original_byte ^ 0x01
        blob = blob[:i] + bytes([tampered_byte]) + blob[i + 1:]
        tampered_idx = i
        ui.system(
            f"[prueba] se alteró 1 byte del ciphertext: "
            f"byte original = 0x{original_byte:02x} -> byte alterado = 0x{tampered_byte:02x}"
        )
    ui.sent_ciphertext(blob, tampered_idx=tampered_idx)
    protocol.send_frame(sock, protocol.DATA, blob)


def run_chat(sock: socket.socket, cipher: SessionCipher, peer_name: str) -> None:
    closing = threading.Event()
    ui.prompt_enabled = True
    threading.Thread(target=_receiver, args=(sock, cipher, peer_name, closing),
                     daemon=True).start()
    ui.system(f"chat con {peer_name} listo. {HELP}")
    try:
        while not closing.is_set():
            line = input().strip()  # el prompt lo dibuja ui (cada salida lo repone)
            if not line:
                ui.reprompt()
                continue
            if line == "/quit":
                break
            if line == "/help":
                ui.system(HELP)
            elif line.startswith("/tamper"):
                text = line[len("/tamper"):].strip()
                if text:
                    _send(sock, cipher, text, tamper=True)
                else:
                    ui.system("uso: /tamper <texto>")
            elif line.startswith("/"):
                ui.system(f"comando desconocido. {HELP}")
            else:
                _send(sock, cipher, line)
    except (KeyboardInterrupt, EOFError):
        pass
    except OSError as e:
        ui.system(f"error de red: {e}")
    finally:
        was_closing = closing.is_set()
        closing.set()
        if not was_closing:
            try:
                protocol.send_frame(sock, protocol.BYE)
            except OSError:
                pass
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("\nsesión finalizada")
