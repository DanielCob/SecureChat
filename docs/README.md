# SecureChat

Aplicacion de consola en Python 3 para mantener conversaciones bidireccionales seguras entre dos procesos locales en localhost (127.0.0.1) mediante criptografia hibrida (RSA-2048 con OAEP y AES-256-GCM).

## 1. Instalacion de Dependencias

### Requisitos previos
- Python 3.10 o superior.

### Pasos de instalacion
1. Crear y activar un entorno virtual:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
   *(En Windows PowerShell: `.venv\Scripts\Activate.ps1`)*

2. Instalar las dependencias del proyecto:
   ```bash
   pip install -r requirements.txt
   ```

## 2. Instrucciones de Ejecucion

Abra dos terminales desde la raiz del proyecto para iniciar cada instancia. En la primera ejecucion, cada participante generara su par de claves RSA en `keys/<nombre>_private.pem`.

### Instancia 1: Servidor (Bob - Escucha)
Execute en la primera terminal:
```bash
python -m securechat listen --name Bob --port 5000
```

### Instancia 2: Cliente (Alice - Conectar)
Ejecute en la segunda terminal:
```bash
python -m securechat connect --name Alice --port 5000
```

### Comandos disponibles durante el chat
- `/help`: Muestra los comandos disponibles.
- `/tamper <texto>`: Envía un mensaje con un byte alterado para probar la detección de manipulación.
- `/quit`: Cierra la sesion de forma controlada.

## 3. Guia para Reproducir la Demostracion

1. **Establecer conexion:** Abra dos terminales lado a lado y ejecute `listen` (Bob) y `connect` (Alice).
2. **Verificar Handshake:** Confirme que ambas terminales muestren la indicacion de que la sesion segura ha sido establecida.
3. **Conversacion bidireccional:** Envie al menos 3 mensajes desde cada extremo. Verifique en cada terminal la visualizacion del plaintext local, el ciphertext transmitido por el socket y el plaintext recuperado en el receptor.
4. **Prueba de alteracion (Tamper):** En una terminal, escriba `/tamper <mensaje>`. Verifique que el extremo receptor detecte la alteracion del authentication tag, muestre el mensaje de rechazo en pantalla y no exponga texto plano corrupto.
5. **Finalizar sesion:** Escriba `/quit` en cualquiera de las terminales para cerrar la conexion TCP de forma limpia.