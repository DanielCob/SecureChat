# SecureChat

Aplicación de consola en Python 3 para mantener conversaciones bidireccionales seguras entre dos procesos locales en localhost (127.0.0.1) mediante criptografía híbrida: RSA-2048 con OAEP para establecer la sesión y AES-256-GCM para proteger cada mensaje.

Video de demostración: https://www.youtube.com/watch?v=_XFWN0-P8VU

## 1. Instalación de dependencias

Requiere Python 3.10 o superior.

1. Crear y activar un entorno virtual:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
   *(En Windows PowerShell: `.venv\Scripts\Activate.ps1`)*

2. Instalar las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## 2. Ejecución

Abra dos terminales desde la raíz del proyecto. En la primera ejecución, cada participante genera su par RSA en `keys/<nombre>_private.pem` (permisos 600; la clave privada nunca se imprime ni se envía por el socket).

**Instancia 1: escucha (Bob)**
```bash
python -m securechat listen --name Bob --port 5000
```

**Instancia 2: se conecta (Alice).** Reintenta unos segundos si la otra aún no está lista.
```bash
python -m securechat connect --name Alice --port 5000
```

Comandos durante el chat:
- `/help`: muestra los comandos disponibles.
- `/tamper <texto>`: envía un mensaje con un byte del ciphertext alterado, para probar la detección de manipulación.
- `/quit`: cierra la sesión de forma controlada.

Colores de la consola: gris = eventos del sistema, verde = plaintext local, amarillo = ciphertext enviado, magenta = ciphertext recibido, cian = plaintext recuperado, rojo = mensaje rechazado.

Pruebas automáticas: `python -m pytest -q`.

## 3. Guía para reproducir la demostración

1. **Conexión:** abra dos terminales lado a lado y ejecute `listen` (Bob) y `connect` (Alice).
2. **Handshake:** confirme que ambas muestran `SESIÓN SEGURA ESTABLECIDA` y compare las huellas de las claves públicas.
3. **Conversación bidireccional:** envíe al menos 3 mensajes desde cada extremo. En cada terminal se ve el plaintext local, el ciphertext enviado, el ciphertext recibido y el plaintext recuperado.
4. **Prueba de alteración:** escriba `/tamper hola`. El receptor muestra `MENSAJE RECHAZADO` y no muestra ningún plaintext; la sesión sigue activa.
5. **Finalizar:** escriba `/quit`.

## 4. Descripción del protocolo

- **Asimétrico:** RSA de 2048 bits con padding OAEP (SHA-256, MGF1-SHA-256). Solo protege la clave de sesión durante el handshake.
- **Simétrico:** AES-256-GCM (clave de 256 bits generada aleatoriamente en cada sesión, nonce de 96 bits, tag de 128 bits). Protege todos los mensajes del chat.
- **Trama de red:** `Longitud (4 B) || Tipo (1 B) || Payload (N B)`, con tipos `HELLO`, `PUBKEY`, `SESSION_KEY`, `READY`, `DATA` y `BYE`.
- **Payload protegido (`DATA` y `READY`):** `Nonce (12 B) || Ciphertext || Tag (16 B)`. El nonce son 4 bytes de dirección (1 = iniciador→respondedor, 2 = respondedor→iniciador) y 8 bytes de contador creciente.

**Handshake** (el iniciador es quien hace `connect`):

1. Ambos envían `HELLO` (nombre) y `PUBKEY` (clave pública en PEM).
2. El iniciador genera la clave de sesión de 32 bytes y la envía en `SESSION_KEY`, cifrada con la clave pública del respondedor (RSA-OAEP).
3. El respondedor la descifra con su clave privada y responde `READY`, que es `b"READY"` cifrado con AES-GCM. Si el iniciador lo verifica, ambos extremos comparten la misma clave y la sesión queda establecida.

**Mensajes:** cada mensaje se cifra con un nonce nuevo y viaja en `DATA`. El receptor verifica el tag y el nonce antes de aceptar el plaintext; si falla, lo rechaza.

**Limitación conocida:** las claves públicas no están autenticadas, por lo que un atacante activo que se interponga en el handshake podría suplantar a un participante. Para mitigarlo, cada extremo muestra la huella de la clave pública del otro y deben compararla manualmente.

## 5. Preguntas de cierre

**1. ¿Qué problema resuelve la criptografía asimétrica durante el handshake?**
Permite que dos partes que aún no comparten ningún secreto acuerden una clave simétrica sin enviarla en claro. El iniciador cifra la clave de sesión con la clave pública del otro, que puede ser conocida por todos, y solo quien tiene la clave privada correspondiente puede recuperarla.

**2. ¿Por qué la conversación utiliza criptografía simétrica después del handshake?**
Porque es mucho más rápida y eficiente que RSA para cifrar muchos mensajes, y RSA solo puede cifrar mensajes muy cortos. Además AES-GCM aporta integridad y autenticidad de cada mensaje, no solo confidencialidad.

**3. ¿Qué información puede observar un tercero que capture los paquetes de la conversación?**
Puede ver los nombres de los participantes (`HELLO` viaja en claro), las claves públicas, la clave de sesión cifrada con RSA, los tipos y tamaños de cada trama, y, de cada mensaje, el nonce, el ciphertext y el tag. Por el nonce puede deducir cuántos mensajes se han enviado y en qué dirección, y por la longitud del ciphertext, la longitud aproximada de cada mensaje. No puede ver el contenido de los mensajes ni la clave de sesión.

**4. ¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?**
El nonce no es un secreto: la seguridad de AES-GCM depende de la clave, no de ocultar el nonce, y el receptor lo necesita para descifrar. En cambio, repetir un nonce con la misma clave rompe la seguridad: permite obtener el XOR de dos plaintexts y recuperar el valor interno con el que GCM calcula el tag, con lo que un atacante podría falsificar mensajes. Aquí se evita usando un contador creciente por dirección, y el receptor rechaza cualquier nonce repetido o fuera de orden.

**5. ¿Qué función cumple el authentication tag?**
Garantiza integridad y autenticidad: solo quien conoce la clave de sesión puede producir un tag válido para un ciphertext. Si alguien altera aunque sea un byte del ciphertext, del nonce o del propio tag, la verificación falla y el receptor descarta el mensaje sin mostrar plaintext, como se demuestra con `/tamper`.

**6. ¿Qué ocurriría si la clave de sesión se transmitiera sin protección?**
Cualquiera que capturara el handshake obtendría la clave y podría descifrar toda la conversación y fabricar mensajes válidos que el receptor aceptaría, porque tendrían tags correctos. El cifrado y la autenticación de AES-GCM no servirían de nada, ya que toda su seguridad depende de que la clave sea secreta.

**7. ¿Qué ocurriría si un atacante obtiene una de las claves privadas?**
Si obtiene la clave privada del respondedor (quien hace `listen`), puede descifrar la clave de sesión de cualquier handshake que haya capturado, y con ella leer y falsificar esas conversaciones, incluidas las pasadas, porque este diseño no tiene secreto hacia adelante. También podría hacerse pasar por ese participante. Si obtiene la clave privada del iniciador, no puede descifrar las sesiones, porque la clave de sesión se cifra con la clave pública del respondedor, pero sí podría suplantar su identidad. Por eso la clave privada nunca viaja por la red, se guarda con permisos restringidos y no se imprime. Una mejora sería usar un intercambio efímero (ECDHE) para tener secreto hacia adelante.
