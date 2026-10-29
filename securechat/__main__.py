"""Punto de entrada. RESPONSABLE: Integrante A.

Uso (dos terminales, mismo proyecto):
    python -m securechat listen  --name Bob   --port 5000
    python -m securechat connect --name Alice --port 5000

Solo escucha/conecta en 127.0.0.1 (nunca 0.0.0.0).
"""
import argparse
import os
import socket
import sys
import time

from . import chat, handshake, keys, protocol, ui

HOST = "127.0.0.1"


def _listen(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)
    ui.system(f"esperando conexión en {HOST}:{port} ...")
    sock, addr = srv.accept()
    srv.close()
    ui.system(f"conexión entrante desde {addr[0]}:{addr[1]}")
    return sock


def _connect(port: int, retries: int = 10) -> socket.socket:
    for attempt in range(retries):
        try:
            sock = socket.create_connection((HOST, port), timeout=5)
            sock.settimeout(None)
            ui.system(f"conectado a {HOST}:{port}")
            return sock
        except OSError:
            if attempt == retries - 1:
                raise
            ui.system(f"sin respuesta en {HOST}:{port}, reintentando ({attempt + 1}/{retries})")
            time.sleep(1)
    raise AssertionError("unreachable")


def main() -> int:
    ap = argparse.ArgumentParser(prog="securechat", description="Chat cifrado sobre localhost")
    ap.add_argument("mode", choices=["listen", "connect"])
    ap.add_argument("--name", required=True, help="tu nombre (p. ej. Alice o Bob)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--keys-dir", default="keys", help="carpeta de claves (default: keys)")
    args = ap.parse_args()

    os.makedirs(args.keys_dir, exist_ok=True)
    priv = keys.load_or_create_keypair(os.path.join(args.keys_dir, f"{args.name}_private.pem"))
    ui.system(f"tu clave: {keys.describe_private_key(priv)}")
    ui.system(f"huella de tu clave pública: {keys.fingerprint(priv.public_key())}")

    try:
        sock = _listen(args.port) if args.mode == "listen" else _connect(args.port)
    except OSError as e:
        ui.system(f"no se pudo establecer la conexión: {e}")
        return 1

    ui.system("iniciando handshake (RSA-OAEP) ...")
    try:
        res = handshake.perform_handshake(sock, args.name, priv,
                                          is_initiator=(args.mode == "connect"))
    except (handshake.HandshakeError, protocol.ConnectionClosed, OSError) as e:
        ui.system(f"handshake fallido: {e}")
        sock.close()
        return 1
    ui.system(f"SESIÓN SEGURA ESTABLECIDA con {res.peer_name}")
    ui.system(f"huella de {res.peer_name}: {res.peer_fingerprint}  (compárenla a mano)")
    ui.system(f"clave de sesión cifrada con RSA que cruzó la red: {res.wrapped_key.hex()[:64]}...")

    chat.run_chat(sock, res.cipher, res.peer_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
