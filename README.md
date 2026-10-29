# SecureChat

Chat cifrado entre dos procesos locales: RSA-2048 (OAEP) para establecer la sesión y AES-256-GCM para cada mensaje.

> Esqueleto. A: instalación y ejecución. B: protocolo y preguntas de cierre. Ver `PLAN.md`.

## Instalación  _(A)_
Requiere Python 3.10+.
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución  _(A)_
Una terminal por participante, desde la raíz del proyecto. Primero el que escucha:
```bash
python -m securechat listen  --name Bob   --port 5000
```
Luego el que se conecta (reintenta unos segundos si el otro aún no está listo):
```bash
python -m securechat connect --name Alice --port 5000
```
Solo usa `127.0.0.1`. En la primera ejecución cada participante genera su par RSA-2048 en `keys/<nombre>_private.pem` (permisos 600, no se sube a git y nunca se imprime ni se envía).

Comandos dentro del chat: `/help`, `/quit` (cierre ordenado) y `/tamper <texto>` (prueba de manipulación).

Colores de la consola: gris = eventos del sistema, verde = tu plaintext, amarillo = ciphertext enviado, magenta = ciphertext recibido, cian = plaintext recuperado, rojo = mensaje rechazado.

## Reproducir la demostración  _(A)_
1. Abrir dos terminales lado a lado y arrancar `listen` (Bob) y `connect` (Alice).
2. Verificar que ambas muestran `SESIÓN SEGURA ESTABLECIDA` y comparar las huellas.
3. Enviar al menos 3 mensajes desde cada lado y comparar, por mensaje, el plaintext local con el ciphertext enviado (amarillo) y el recibido (magenta) y el plaintext recuperado (cian).
4. En una terminal escribir `/tamper hola`: se cifra, se altera 1 byte del ciphertext y se envía. El otro extremo muestra `MENSAJE RECHAZADO` en rojo y no muestra plaintext; la sesión sigue activa.
5. Terminar con `/quit`.

Pruebas automáticas: `python -m pytest -q`.

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
