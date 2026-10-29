# SecureChat – Plan de implementación y división de trabajo

A = Integrante 1 (red, UI, README) · B = Integrante 2 (criptografía, handshake lógico, protocolo).
Entrega: código + README + video (4–6 min). Ambos deben entender TODO el flujo para el video.

## 1. Cómo se divide el código (un archivo = un dueño)

| Archivo | Paso | Dueño | Estado inicial |
|---|---|---|---|
| `securechat/protocol.py` | 1 | A | **Hecho** (framing + tipos de frame; es el contrato) |
| `securechat/__main__.py` | 1 | A | Stub con el flujo documentado |
| `securechat/chat.py` | 1, 5, 6 | A | Stub (hilos envío/recepción, `/quit`, `/tamper`) |
| `securechat/ui.py` | 5 | A | Stub (colores y funciones de salida) |
| `securechat/keys.py` | 2 | **B** | Stub con firmas + docstrings |
| `securechat/session_crypto.py` | 4 | **B** | Stub (`SessionCipher`, política de nonce) |
| `securechat/handshake.py` | 3 | **B** (A integra) | Stub (diagrama del flujo + `perform_handshake`) |
| `tests/test_protocol.py` | 1 | A | Hecho |
| `tests/test_keys.py`, `test_session_crypto.py`, `test_handshake.py` | 2–4 | B | **Escritos como especificación**: B termina cuando pasan |
| `README.md` | 7 | A (B aporta protocolo y preguntas) | Esqueleto |

Regla: nadie edita el archivo del otro; si hay que cambiar un contrato, se acuerda y se actualiza este documento.

## 2. Protocolo (resumen del contrato)

Frame: `longitud(4B BE) | tipo(1B) | payload`. Tipos: `HELLO, PUBKEY, SESSION_KEY, READY, DATA, BYE`.

Handshake (iniciador = `connect`, respondedor = `listen`):
1. Ambos envían `HELLO(nombre)` y `PUBKEY(PEM)`.
2. Iniciador genera clave de sesión de 32 B (`os.urandom`), la envía como `SESSION_KEY = RSA-OAEP(SHA-256)(pub_respondedor, clave)`.
3. Respondedor descifra con su privada y responde `READY = AES-GCM(b"READY")`; el iniciador lo verifica → sesión establecida.

Mensajes: `DATA` = `nonce(12) || ciphertext || tag(16)`, AES-256-GCM.
Nonce = `dirección(4B) || contador(8B)`; el receptor exige contador estrictamente creciente (anti-repetición).

Fuera de alcance (decirlo en el README): las claves públicas no están autenticadas → un intermediario activo podría suplantar; se mitiga mostrando la **huella** para comparar a mano.

## 3. Interfaces que A necesita de B (firmas fijas)

```python
keys.load_or_create_keypair(path) -> RSAPrivateKey
keys.describe_private_key(priv) -> str          # seguro para imprimir
keys.fingerprint(pub) -> str
handshake.perform_handshake(sock, name, priv, is_initiator) -> HandshakeResult
    # .cipher .peer_name .peer_fingerprint .wrapped_key
SessionCipher.encrypt(bytes) -> bytes           # blob nonce||ct||tag
SessionCipher.decrypt(bytes) -> bytes           # lanza InvalidMessage
session_crypto.split_blob(blob) -> (nonce, ct, tag)
```

## 4. Orden de trabajo (para que nadie espere al otro)

Los dos arrancan a la vez porque `protocol.py` ya existe y los tests de B usan `socket.socketpair()` (no necesitan la red de A).

| Fase | A | B |
|---|---|---|
| 1 | Paso 1: `__main__` (listen/connect) y `chat.py` con **bytes en claro** solo para probar conectividad; `ui.py` | `keys.py` + `test_keys.py` en verde |
| 2 | Seguir con UI/hilos; `/quit` limpio | `session_crypto.py` + `test_session_crypto.py` en verde |
| 3 | Esperar `HandshakeResult`; preparar `/tamper` | `handshake.py` + `test_handshake.py` en verde |
| 4 | Integrar: `__main__` → handshake → `run_chat` (quitar el modo en claro) | Revisar integración; probar con A |
| 5 | Paso 6 (`/tamper`) y ensayo del video | Paso 6: comprobar rechazo sin mostrar basura |
| 6 | README + guía de ejecución | Descripción del protocolo + 7 preguntas de cierre |
| 7 | **Ambos**: grabar el video (guion abajo) |

Comando de verificación de cada uno: `python -m pytest tests/test_<su_modulo>.py -q`.

## 5. Checklist de aceptación (requisitos mínimos del enunciado)

- [ ] Dos instancias simultáneas por TCP en `127.0.0.1` (solo localhost).
- [ ] RSA ≥ 2048 con OAEP; privada nunca por el socket ni impresa.
- [ ] Clave de sesión generada al vuelo, nunca en claro ni hardcodeada.
- [ ] Sesión establecida se anuncia en pantalla antes del primer mensaje.
- [ ] AES-256-GCM; nonce nunca repetido; tag verificado antes de mostrar plaintext.
- [ ] La UI distingue: plaintext local / ciphertext enviado / ciphertext recibido / plaintext recuperado.
- [ ] ≥ 3 mensajes en cada dirección; salida controlada (`/quit`).
- [ ] `/tamper` → el receptor rechaza y no muestra plaintext; la sesión sigue viva.
- [ ] Sin Base64/hex como “cifrado”, sin ECB (el hex solo se usa para *mostrar*).
- [ ] README (instalación, ejecución, protocolo: algoritmos, tamaños, estructura de mensajes) + 7 preguntas.

## 6. Guion del video (4–6 min, ambos hablan)

1. (A) Dos terminales lado a lado; arrancar `listen` y `connect`; mostrar huellas y “sesión segura establecida”.
2. (B) Explicar el handshake: dónde se usa RSA y por qué la clave de sesión no viaja en claro.
3. (A→B) 3 mensajes de Alice y 3 de Bob; señalar plaintext local / ciphertext enviado / recibido / recuperado.
4. (B) Explicar AES-GCM, nonce y tag con un mensaje real en pantalla.
5. (A) `/tamper hola` → rechazo en el receptor; (B) explicar por qué el tag lo detecta.
6. (Ambos) Cierre con `/quit` y resumen asimétrica vs simétrica.

## 7. Cómo se pasan los archivos

Pasar la carpeta completa (sin `keys/*.pem`, ya está en `.gitignore`). B hace:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/test_keys.py -q        # luego test_session_crypto, test_handshake
```
Cada `TODO(B)` marca exactamente lo que falta; los docstrings dicen qué debe cumplir.
