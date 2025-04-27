
# Sistema de Autenticación TOTP "The Coder Sensei"

Este proyecto implementa un sistema de autenticación de dos factores (2FA) seguro utilizando contraseñas de un solo uso basadas en tiempo (TOTP). Genera códigos QR para una fácil configuración con aplicaciones de autenticación como Google Authenticator, Authy o similares.

**Este script se basa en el estándar RFC 6238: [https://datatracker.ietf.org/doc/html/rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)**

**Este proyecto está disponible en: [https://github.com/DogSoulDev/The-Codeitor-Sensei](https://github.com/DogSoulDev/The-Codeitor-Sensei)**

## Tabla de Contenidos

-   [Características](#características)
-   [Requisitos Previos](#requisitos-previos)
-   [Instalación](#instalación)
-   [Configuración](#configuración)
-   [Uso](#uso)
-   [Explicación del Código](#explicación-del-código)
-   [Consideraciones de Seguridad](#consideraciones-de-seguridad)
-   [Contribución](#contribución)
-   [Licencia](#licencia)
-   [Solución de Problemas](#solución-de-problemas)

## Características

-   **Generación Segura de TOTP:** Genera secretos TOTP seguros y códigos QR para la autenticación.
-   **Generación de Códigos QR:** Crea códigos QR que se pueden escanear con aplicaciones de autenticación.
-   **Verificación de Dependencias:** Verifica que todas las dependencias necesarias estén instaladas.
-   **Configuración del Entorno:** Utiliza variables de entorno para la configuración.
-   **Registro (Logging):** Registra los intentos de autenticación y los errores para la auditoría y la resolución de problemas.
-   **Limitación de Tasa (Rate Limiting):** Implementa la limitación de tasa para evitar ataques de fuerza bruta.
-   **Expiración del Código QR:** Los códigos QR expiran después de un cierto período de tiempo.
-   **Manejo Seguro de Secretos:** Borra la información confidencial de la memoria después de su uso.

## Requisitos Previos

Antes de comenzar, asegúrate de tener lo siguiente instalado:

-   **Python 3.6+:** Este proyecto requiere Python 3.6 o superior. Puedes descargarlo desde [python.org](https://www.python.org/downloads/).
-   **pip:** El instalador de paquetes de Python. Por lo general, viene con Python.

## Instalación

1.  **Clona el repositorio:**

    ```bash
    git clone https://github.com/DogSoulDev/The-Codeitor-Sensei
    cd The-Codeitor-Sensei
    ```

2.  **Instala las dependencias:**

    ```bash
    pip install -r requirements.txt
    ```

    Este comando instalará todos los paquetes de Python necesarios que se enumeran en el archivo `requirements.txt`. Si encuentras algún problema, asegúrate de que tu `pip` esté actualizado:

    ```bash
    pip install --upgrade pip
    ```

    El archivo `requirements.txt` contiene las siguientes dependencias:

    ```
    pyotp==2.9.0
    qrcode==7.4.2
    colorama==0.4.6
    python-dotenv==1.0.0
    importlib_metadata==7.0.1
    ```

## Configuración

El script utiliza variables de entorno para la configuración. Puedes establecer estas variables en tu shell o en un archivo `.env` en el directorio del proyecto. Aquí hay una lista de las opciones de configuración disponibles:

-   `QR_EXPIRATION`: El tiempo de expiración para los códigos QR en segundos (predeterminado: 300).
-   `MAX_ATTEMPTS`: El número máximo de intentos de autenticación permitidos (predeterminado: 5).
-   `ALLOWED_ISSUERS`: Una lista separada por comas de los emisores permitidos para el TOTP (predeterminado: "TheCodeitorSensei,KaliLinuxSec").
-   `QR_DIR`: El directorio donde se almacenan los códigos QR (predeterminado: "generated\_qrs").
-   `SECRET_ENV_VAR`: El nombre de la variable de entorno donde se almacena el secreto TOTP (predeterminado: "TOTP\_MASTER\_SECRET").
-   `RATE_LIMIT_TIME_WINDOW`: El intervalo de tiempo para la limitación de tasa en segundos (predeterminado: 60).
-   `RATE_LIMIT_MAX_ATTEMPTS`: El número máximo de intentos permitidos dentro del intervalo de tiempo de limitación de tasa (predeterminado: 3).

Ejemplo de archivo `.env`:


Para cargar estas variables, asegúrate de tener el paquete `python-dotenv` instalado (está en `requirements.txt`) y de llamar a `load_dotenv()` en tu script.

## Uso

1.  **Ejecuta el script:**

    ```bash
    python coder.py
    ```

2.  **Sigue las indicaciones:**

    -   El script generará un código QR y mostrará un URI.
    -   Escanea el código QR con tu aplicación de autenticación (por ejemplo, Google Authenticator).
    -   Ingresa el código TOTP de la aplicación de autenticación cuando se te solicite.

## Explicación del Código

Aquí hay un resumen de las partes principales del código:

-   **Importaciones:** El script importa bibliotecas necesarias como `pyotp` (para la generación de TOTP), `qrcode` (para la generación de códigos QR), `colorama` (para la salida de terminal en color) y otras.
-   **Configuración:** La clase `Config` lee los valores de configuración de las variables de entorno. Esto facilita el cambio de la configuración sin modificar el código.
-   **Registro (Logging):** El script utiliza el módulo `logging` para registrar eventos, errores e intentos de autenticación. Esto es útil para la depuración y la auditoría.
-   **`check_dependencies()`:** Esta función verifica que todos los paquetes de Python requeridos estén instalados. Si falta alguno, imprime instrucciones sobre cómo instalarlos usando `pip`.
-   **`secure_filename()`:** Esta función genera un nombre de archivo seguro para la imagen del código QR utilizando un hash del secreto.
-   **`setup_environment()`:** Esta función crea el directorio del código QR si no existe y establece los permisos adecuados.
-   **`generate_secret()`:** Genera una clave secreta segura utilizando el módulo `secrets`.
-   **`generar_qr_totp()`:** Esta función genera el código QR para el secreto TOTP. Toma el emisor y el nombre de la cuenta como argumentos y devuelve el secreto, la ruta del código QR y el URI.
-   **`validar_totp()`:** Esta función valida el código TOTP ingresado por el usuario contra el secreto.
-   **`limpiar_qrs_antiguos()`:** Esta función elimina los códigos QR antiguos que han expirado.
-   **`is_rate_limited()`:** Esta función verifica si una dirección IP está limitada en función de la cantidad de intentos fallidos dentro de un cierto período de tiempo.
-   **`authenticate_totp()`:** Esta es la función principal de autenticación. Genera el código QR, le pide al usuario que lo escanee y luego solicita el código TOTP. También maneja la limitación de tasa y la expiración del código QR.
-   **`if __name__ == "__main__":`:** Este es el punto de entrada principal del script. Llama a la función `check_dependencies()` para verificar que todas las dependencias estén instaladas, carga las variables de entorno y luego llama a la función `authenticate_totp()` para iniciar el proceso de autenticación.

## Consideraciones de Seguridad

-   **Variables de Entorno:** Ten cuidado con cómo almacenas y administras las variables de entorno, especialmente en entornos de producción. Evita confirmar archivos `.env` al control de versiones.
-   **Almacenamiento de Códigos QR:** Los códigos QR se almacenan en un directorio con permisos restringidos. Asegúrate de que este directorio no sea accesible para usuarios no autorizados.
-   **Limitación de Tasa:** La limitación de tasa se implementa para evitar ataques de fuerza bruta. Ajusta las opciones de configuración `RATE_LIMIT_TIME_WINDOW` y `RATE_LIMIT_MAX_ATTEMPTS` para que se adapten a tus necesidades.
-   **Manejo de Secretos:** El script borra el secreto TOTP de la memoria después de su uso para evitar que se acceda a él más tarde. Sin embargo, considera utilizar métodos más seguros para almacenar secretos, como módulos de seguridad de hardware (HSM) o servicios de administración de secretos.

## Contribución

¡Las contribuciones son bienvenidas! Si encuentras un error o tienes una idea para una nueva función, abre un problema o envía una solicitud de extracción.

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).

## Solución de Problemas

-   **Problemas con `pip`:** Si encuentras errores durante la instalación de dependencias, intenta actualizar `pip` primero:

    ```bash
    python -m pip install --upgrade pip
    ```

    Luego, intenta instalar las dependencias nuevamente:

    ```bash
    pip install -r requirements.txt
    ```

-   **Problemas con la aplicación de autenticación:** Si el código TOTP no funciona, asegúrate de que el reloj de tu sistema esté sincronizado. Algunas aplicaciones de autenticación también tienen opciones para corregir la desviación del tiempo.

-   **Problemas con las variables de entorno:** Verifica que todas las variables de entorno necesarias estén configuradas correctamente. Utiliza `printenv` en tu terminal para listar todas las variables de entorno.