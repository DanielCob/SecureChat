"""Punto de entrada. RESPONSABLE: Integrante A.

Uso (dos terminales, mismo proyecto):
    python -m securechat listen  --name Bob   --port 5000
    python -m securechat connect --name Alice --port 5000        # host por defecto 127.0.0.1

Flujo:
    1. argparse: modo (listen|connect), --name, --port, [--host 127.0.0.1]
    2. priv = keys.load_or_create_keypair(f"keys/{name}_private.pem")   # B
       ui.system(keys.describe_private_key(priv))
    3. listen: bind+listen+accept (SO_REUSEADDR) | connect: connect (reintentos cortos)
       ui.system("conectado con <addr>")                                # Paso 1
    4. res = handshake.perform_handshake(sock, name, priv, is_initiator=(mode == "connect"))
       ui.system(f"sesion segura establecida con {res.peer_name} (huella {res.peer_fingerprint})")
    5. chat.run_chat(sock, res.cipher, res.peer_name)
    Manejar HandshakeError y ConnectionClosed con mensaje claro y codigo de salida != 0.
    Escuchar solo en 127.0.0.1 (nunca 0.0.0.0).
"""


def main() -> None:
    # TODO(A)
    raise NotImplementedError


if __name__ == "__main__":
    main()
