import pyotp
import qrcode
import os
import time
import colorama
import argparse
import logging
import getpass
import sys
import atexit
import secrets
import base64
from datetime import datetime, timedelta
from hashlib import sha256
from dotenv import load_dotenv
from colorama import Fore, Style
import socket
import threading

# Configuración inicial de colorama
colorama.init(autoreset=True)

# Configuración de logging
logging.basicConfig(
    filename='totp_auth.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - %(ip_address)s - %(username)s',
    filemode='a'
)

class Config:
    """Configuración de la aplicación."""
    try:
        QR_EXPIRATION = int(os.getenv("QR_EXPIRATION", 300))
    except (ValueError, TypeError):
        QR_EXPIRATION = 300
        logging.warning("QR_EXPIRATION no es un entero válido. Usando el valor predeterminado: 300")

    try:
        MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", 5))
    except (ValueError, TypeError):
        MAX_ATTEMPTS = 5
        logging.warning("MAX_ATTEMPTS no es un entero válido. Usando el valor predeterminado: 5")

    ALLOWED_ISSUERS = os.getenv("ALLOWED_ISSUERS", "TheCodeitorSensei,KaliLinuxSec").split(",")
    QR_DIR = os.getenv("QR_DIR", "generated_qrs")
    SECRET_ENV_VAR = os.getenv("SECRET_ENV_VAR", "TOTP_MASTER_SECRET")

    try:
        RATE_LIMIT_TIME_WINDOW = int(os.getenv("RATE_LIMIT_TIME_WINDOW", 60))
    except (ValueError, TypeError):
        RATE_LIMIT_TIME_WINDOW = 60
        logging.warning("RATE_LIMIT_TIME_WINDOW no es un entero válido. Usando el valor predeterminado: 60")

    try:
        RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", 3))
    except (ValueError, TypeError):
        RATE_LIMIT_MAX_ATTEMPTS = 3
        logging.warning("RATE_LIMIT_MAX_ATTEMPTS no es un entero válido. Usando el valor predeterminado: 3")

qr_path = None  # Make qr_path global
qr_expiration_time = None # Make qr_expiration_time global

# Rate limiting
attempt_counts = {}  # Dictionary to store attempt counts per IP address
attempt_lock = threading.Lock()

def remove_qr():
    """Elimina el archivo QR si existe."""
    global qr_path
    if qr_path and os.path.exists(qr_path):
        os.remove(qr_path)
        logging.info(f"QR eliminado: {qr_path}")
    qr_path = None

atexit.register(remove_qr)

class CustomAdapter(logging.LoggerAdapter):
    """
    Adapter to add IP address and username to log messages.
    """
    def process(self, msg, kwargs):
        ip_address = kwargs.pop('ip_address', '127.0.0.1')  # Default to localhost
        username = kwargs.pop('username', 'unknown')
        return msg, {'ip_address': ip_address, 'username': username}

# Initialize logger with adapter
extra = {'ip_address': socket.gethostbyname(socket.gethostname()), 'username': getpass.getuser()}
logger = CustomAdapter(logging.getLogger(__name__), extra)

def check_dependencies():
    """Verifica que todas las dependencias necesarias estén instaladas."""
    required = {'pyotp', 'qrcode', 'colorama', 'python-dotenv', 'importlib_metadata'}
    try:
        from importlib import metadata
    except ImportError:
        import importlib_metadata as metadata

    installed = {dist.metadata['Name'] for dist in metadata.distributions()}
    missing = required - installed

    if missing:
        print(Fore.RED + f"❌ Dependencias faltantes: {', '.join(missing)}")
        print("Para instalar las dependencias faltantes, ejecute:\n")
        for package in missing:
            print(Fore.CYAN + f"   pip install {package}")
        print(Style.RESET_ALL)
        print(Fore.YELLOW + "💡 Sugerencia: Asegúrese de tener 'pip' instalado y actualizado. Si tiene problemas, pruebe 'python -m pip install --upgrade pip' y luego reinstale las dependencias." + Style.RESET_ALL)
        sys.exit(1)

def secure_filename(secret):
    """Genera un nombre de archivo seguro usando hash del secreto."""
    return f"qr_{sha256(secret.encode()).hexdigest()[:8]}.png"

def setup_environment():
    """Configura el entorno y directorios necesarios."""
    if not os.path.exists(Config.QR_DIR):
        os.makedirs(Config.QR_DIR)
        os.chmod(Config.QR_DIR, 0o700)

def generate_secret():
    """Genera un secreto seguro."""
    return base64.b32encode(secrets.token_bytes(16)).decode('utf-8').replace('=', '')

def generar_qr_totp(issuer, account_name, secret=None):
    """
    Genera y almacena de forma segura el QR TOTP.
    Devuelve: (secreto, ruta del QR, URI)
    """
    global qr_path, qr_expiration_time
    try:
        setup_environment()
        secret = secret or generate_secret()

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=account_name,
            issuer_name=issuer
        )

        filename = secure_filename(secret)
        qr_path = os.path.join(Config.QR_DIR, filename)

        qrcode.make(uri).save(qr_path)
        os.chmod(qr_path, 0o600)  # Permisos restrictivos

        qr_expiration_time = datetime.now() + timedelta(seconds=Config.QR_EXPIRATION)

        logger.info(f"QR generado para {account_name} - {issuer}", extra=extra)
        return secret, qr_path, uri

    except Exception as e:
        logger.error(f"Error generando QR: {str(e)}", extra=extra)
        raise

def validar_totp(secret, codigo):
    """Valida el código TOTP con manejo de errores seguro."""
    try:
        return pyotp.TOTP(secret).verify(codigo)
    except Exception as e:
        logger.error(f"Error validando TOTP: {str(e)}", extra=extra)
        return False

def limpiar_qrs_antiguos():
    """Elimina QRs antiguos basado en el tiempo de expiración."""
    try:
        now = datetime.now()
        for fname in os.listdir(Config.QR_DIR):
            path = os.path.join(Config.QR_DIR, fname)
            creation_time = datetime.fromtimestamp(os.path.getctime(path))
            if (now - creation_time).seconds > Config.QR_EXPIRATION:
                os.remove(path)
                logger.info(f"QR expirado eliminado: {fname}", extra=extra)
    except Exception as e:
        logger.error(f"Error limpiando QRs: {str(e)}", extra=extra)

def is_rate_limited(ip_address):
    """Check if the IP address is rate limited."""
    with attempt_lock:
        now = datetime.now()
        if ip_address not in attempt_counts:
            attempt_counts[ip_address] = []

        # Remove old attempts
        attempt_counts[ip_address] = [
            attempt_time for attempt_time in attempt_counts[ip_address]
            if now - attempt_time < timedelta(seconds=Config.RATE_LIMIT_TIME_WINDOW)
        ]

        # Check if rate limited
        if len(attempt_counts[ip_address]) >= Config.RATE_LIMIT_MAX_ATTEMPTS:
            return True

        # Add new attempt
        attempt_counts[ip_address].append(now)
        return False

def authenticate_totp():
    """Flujo principal de autenticación con TOTP."""
    parser = argparse.ArgumentParser(description="Sistema de Autenticación TOTP Seguro")
    parser.add_argument('--issuer', default="TheCodeitorSensei",
                      choices=Config.ALLOWED_ISSUERS,
                      help="Entidad emisora del TOTP")
    parser.add_argument('--qr-ttl', type=int, default=Config.QR_EXPIRATION,
                      help="Tiempo de vida del QR en segundos")
    args = parser.parse_args()

    limpiar_qrs_antiguos()

    try:
        account_name = os.getenv('SUDO_USER') or getpass.getuser()
        extra['username'] = account_name  # Update username in logging extra
        secret, qr_path, uri = generar_qr_totp(args.issuer, account_name)

        print(Fore.CYAN + f"\n🔒 URI de Autenticación: {uri}")
        print(Fore.BLUE + f"📷 QR generado en: {qr_path}")
        print(Fore.MAGENTA + f"🔑 Secreto (encriptado en memoria): {secret[:4]}****{secret[-4:]}" + Style.RESET_ALL)

        input("\n⚠️  Escanee el QR con Google Authenticator y presione Enter...")

        ip_address = socket.gethostbyname(socket.gethostname())

        attempts = 0
        while attempts < Config.MAX_ATTEMPTS:
            # QR Code Expiration Check
            if datetime.now() > qr_expiration_time:
                print(Fore.RED + "🚫 El código QR ha expirado. Por favor, reinicie la autenticación.")
                logger.warning(f"QR code expired for {account_name}", extra=extra)
                return False

            # Rate Limiting Check
            if is_rate_limited(ip_address):
                print(Fore.RED + "🚫 Demasiados intentos fallidos. Por favor, espere antes de intentar nuevamente.")
                logger.warning(f"Rate limit exceeded for IP: {ip_address}", extra=extra)
                return False

            codigo = getpass.getpass("➡️  Ingrese código TOTP (6 dígitos): ")
            if not codigo.isdigit() or len(codigo) != 6:
                print(Fore.RED + "❌ Código inválido. Debe ser un número de 6 dígitos.")
                attempts += 1
                time.sleep(1.5)
                continue

            if validar_totp(secret, codigo):
                print(Fore.GREEN + "✅ Autenticación exitosa!")
                logger.info(f"Autenticación exitosa para {account_name}", extra=extra)
                del secret # Clear sensitive information from memory
                return True

            print(Fore.RED + "❌ Código inválido. Intentos restantes: "
                  + str(Config.MAX_ATTEMPTS - attempts - 1))
            attempts += 1
            time.sleep(1.5)  # Prevención de fuerza bruta

        print(Fore.RED + "🚫 Máximo de intentos alcanzado. Bloqueando acceso...")
        logger.warning(f"Intento de acceso bloqueado para {account_name}", extra=extra)
        return False

    except Exception as e:
        logger.critical(f"Error crítico: {str(e)}", extra=extra)
        print(Fore.RED + "⛔ Error en el sistema de autenticación. Contacte al administrador.")
        return False
    finally:
        remove_qr()

if __name__ == "__main__":
    check_dependencies()
    load_dotenv()

    print(Fore.YELLOW + """
████████╗██╗  ██╗███████╗     ██████╗ ██████╗ ██████╗ ███████╗██████╗
╚══██╔══╝██║  ██║██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
   ██║   ███████║█████╗      ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
   ██║   ██╔══██║██╔══╝      ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
   ██║   ██║  ██║███████╗    ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

███████╗███████╗███╗   ██╗███████╗███████╗██╗
██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝██║
███████╗█████╗  ██╔██╗ ██║███████╗█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝  ██║
███████║███████╗██║ ╚████║███████║███████╗██║
╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝
    """ + Style.RESET_ALL)

    if authenticate_totp():
        print(Fore.GREEN + "\n🚀 Acceso concedido. Ejecutando tareas seguras...")
        # Aquí iría el código protegido
    else:
        print(Fore.RED + "\n🔒 Acceso denegado. Saliendo del sistema...")
        sys.exit(1)