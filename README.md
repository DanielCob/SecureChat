# SecureChat

Chat cifrado entre dos procesos locales: RSA-2048 (OAEP) para establecer la sesión y AES-256-GCM para cada mensaje.

> Esqueleto. A: instalación y ejecución. B: protocolo y preguntas de cierre. Ver `PLAN.md`.

## Instalación  _(A)_
TODO

## Ejecución  _(A)_
```bash
python -m securechat listen  --name Bob   --port 5000
python -m securechat connect --name Alice --port 5000
```
Comandos en el chat: `/quit`, `/tamper <texto>`.

## Reproducir la demostración  _(A)_
TODO

## Protocolo  _(B)_
Algoritmo asimétrico, simétrico, tamaños de clave y estructura de mensajes (ver `securechat/protocol.py`). TODO

## Preguntas de cierre  _(B)_
1. ¿Qué problema resuelve la criptografía asimétrica durante el handshake?
2. ¿Por qué la conversación utiliza criptografía simétrica después del handshake?
3. ¿Qué información puede observar un tercero que capture los paquetes?
4. ¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?
5. ¿Qué función cumple el authentication tag?
6. ¿Qué ocurriría si la clave de sesión se transmitiera sin protección?
7. ¿Qué ocurriría si un atacante obtiene una de las claves privadas?
