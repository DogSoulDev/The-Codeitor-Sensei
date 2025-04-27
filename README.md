# Autenticación TOTP "The Coder Sensei"

Este proyecto implementa un sistema de autenticación de dos factores (2FA) seguro utilizando contraseñas de un solo uso basadas en tiempo (TOTP). Genera códigos QR para una configuración sencilla con apps como Google Authenticator, Authy o similares.

**Basado en el estándar RFC 6238:** [https://datatracker.ietf.org/doc/html/rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)

**Disponible en GitHub:** [https://github.com/DogSoulDev/The-Coder-Sensei](https://github.com/DogSoulDev/The-Coder-Sensei)

## Tabla de Contenidos

-   [Características](#características)
-   [Requisitos](#requisitos)
-   [Instalación](#instalación)
-   [Configuración](#configuración)
-   [Uso](#uso)
-   [Funcionamiento](#funcionamiento)
-   [Seguridad](#seguridad)
-   [Contribuir](#contribuir)
-   [Licencia](#licencia)
-   [Ayuda](#ayuda)

## Características

-   **TOTP Seguros:** Genera secretos y códigos QR para autenticación.
-   **Códigos QR:** Compatibles con apps de autenticación.
-   **Variables de Entorno:** Configuración sencilla.
-   **Registro:** Guarda intentos de acceso y errores.
-   **Límite de Intentos:** Evita ataques de fuerza bruta.
-   **QR Expirables:** Mayor seguridad.

## Requisitos

Antes de empezar, necesitas:

-   **Python 3.6+:** Descárgalo desde [python.org](https://www.python.org/downloads/).
-   **pip:** Instalador de paquetes de Python (viene con Python).

## Instalación

1.  **Clona el repositorio:**

    Para clonar el repositorio, usa el siguiente comando en Bash:

    git clone https://github.com/DogSoulDev/The-Coder-Sensei
    cd The-Coder-Sensei

2.  **Crea y activa un entorno virtual:**

    Para crear y activar un entorno virtual, usa los siguientes comandos en Bash:

    python3 -m venv .venv
    source .venv/bin/activate

    ℹ️ Un entorno virtual aísla las dependencias del proyecto.

    **Crear el entorno virtual:**

    Para crear el entorno virtual, usa el siguiente comando en Bash:

    python3 -m venv .venv

    **Activar el entorno virtual:**

    Para activar el entorno virtual, usa el siguiente comando en Bash:

    source .venv/bin/activate

    Verás `(.venv)` al inicio de la línea de comandos.

3.  **Instala las dependencias:**

    Para instalar las dependencias, usa el siguiente comando en Bash:

    pip install -r requirements.txt

    Si hay problemas, actualiza `pip` con el siguiente comando en Bash:

    pip install --upgrade pip

    El archivo `requirements.txt` contiene:

    pyotp==2.9.0
    qrcode[pil]==7.4.2
    colorama==0.4.6
    python-dotenv==1.0.0
    Pillow==10.0.0

4.  **Ejecutar el script:**

    Asegúrate de estar dentro del entorno virtual.

    **Desactivar el entorno virtual:**

    Para desactivar el entorno virtual, usa el siguiente comando en Bash:

    deactivate

    Cuando termines de trabajar en el proyecto, puedes desactivar el entorno virtual. Esto devolverá tu terminal a su estado normal.

## Configuración

El script usa variables de entorno. Puedes definirlas en tu terminal o en un archivo `.env`:

-   `QR_EXPIRATION`: Tiempo de expiración del QR en segundos (por defecto: 300).
-   `MAX_ATTEMPTS`: Número máximo de intentos de acceso (por defecto: 5).
-   `ALLOWED_ISSUERS`: Lista de emisores permitidos (separados por comas).
-   `QR_DIR`: Directorio para guardar los códigos QR (por defecto: "generated\_qrs").
-   `TOTP_MASTER_SECRET`: Variable para guardar el secreto TOTP.

Ejemplo de `.env`:

QR_EXPIRATION=300
MAX_ATTEMPTS=5
ALLOWED_ISSUERS=TheCoderSensei
QR_DIR=generated_qrs
TOTP_MASTER_SECRET=mi_secreto_super_seguro

Carga las variables con `load_dotenv()` (necesitas `python-dotenv`).

## Uso

1.  **Ejecuta el script:**

    Para ejecutar el script, usa el siguiente comando en Bash:

    python coder.py

2.  **Sigue las instrucciones:**

    -   El script genera un código QR.
    -   Escanea el QR con tu app de autenticación.
    -   Introduce el código TOTP cuando se te pida.

## Funcionamiento

El script hace lo siguiente:

-   Importa librerías como `pyotp`, `qrcode`, `colorama`, etc.
-   Lee la configuración desde variables de entorno.
-   Verifica que las dependencias estén instaladas.
-   Genera un secreto con `generate_secret()`.
-   Crea el código QR con `generar_qr_totp()`.
-   Valida el código TOTP con `validar_totp()`.
-   Gestiona el límite de intentos y la expiración del QR.
-   Autentica al usuario con `authenticate_totp()`.

## Seguridad

-   **Variables de Entorno:** No subas el archivo `.env` a Git.
-   **Almacenamiento QR:** Protege el directorio de los códigos QR.
-   **Límite de Intentos:** Ajusta los parámetros para evitar ataques.
-   **Manejo de Secretos:** Considera métodos más seguros para guardar secretos (HSM, etc.).

## Contribuir

¡Las contribuciones son bienvenidas! Abre un "issue" o envía un "pull request".

## Licencia

Este proyecto usa la [MIT License](LICENSE).

## Ayuda

### Problemas con `pip`

Para actualizar `pip` y luego instalar las dependencias, usa los siguientes comandos en Bash:

python -m pip install --upgrade pip
pip install -r requirements.txt

### Problemas con la app de autenticación

Sincroniza el reloj de tu sistema.

### Problemas con las variables de entorno

Verifica que estén definidas correctamente.