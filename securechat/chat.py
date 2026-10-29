"""Pasos 1, 5 y 6 - Bucle de chat concurrente. RESPONSABLE: Integrante A.

run_chat(sock, cipher, peer_name):
  - Hilo receptor (daemon): recv_frame en bucle.
        DATA -> ui.received_ciphertext(blob); try cipher.decrypt(blob)
                  ok  -> ui.recovered_plaintext(peer_name, texto)
                  InvalidMessage -> ui.rejected(...)   # NO mostrar plaintext, NO cerrar la sesion
        BYE / ConnectionClosed -> ui.system("el par cerro la sesion"); avisar al hilo principal
  - Hilo principal: input() en bucle.
        texto normal -> ui.local_plaintext(t); blob = cipher.encrypt(t.encode());
                        ui.sent_ciphertext(blob); send_frame(sock, DATA, blob)
        /quit        -> send_frame(BYE); cerrar socket limpiamente
        /tamper <t>  -> Paso 6: igual que arriba pero voltea 1 byte del ciphertext
                        (indice >= NONCE_LEN y < len-TAG_LEN) DESPUES de cifrar y antes de enviar;
                        mostrar que se alteró. El receptor debe rechazarlo.
  - Solo el hilo principal envia (si algun dia envian dos hilos, proteger con Lock).
  - Cuando el par se desconecta el hilo principal debe salir sin quedar bloqueado en input().
"""
import socket

from .session_crypto import SessionCipher


def run_chat(sock: socket.socket, cipher: SessionCipher, peer_name: str) -> None:
    # TODO(A)
    raise NotImplementedError
