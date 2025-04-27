import pyotp
import qrcode
import os
import time
import colorama
import logging
import getpass
import sys
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from hashlib import sha256
import socket
import shutil
from typing import Optional
from urllib.parse import quote, urlencode
from colorama import Fore, Style
from dotenv import load_dotenv
from io import BytesIO
from PIL import Image

# Initialize logger
logger = logging.getLogger(__name__)

# Configuración inicial de colorama
colorama.init(autoreset=True)

# Configuración del registro de eventos
logging.basicConfig(
    filename='totp_auth.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - %(ip_address)s - %(username)s',
    filemode='a'
)

class Config:
    """Configuración de la aplicación."""
    QR_EXPIRATION = int(os.getenv("QR_EXPIRATION", "300"))
    MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "5"))
    ALLOWED_ISSUERS = os.getenv("ALLOWED_ISSUERS", "TheCoderSensei").split(",")
    QR_DIR = os.getenv("QR_DIR", "generated_qrs")
    SECRET_ENV_VAR = os.getenv("SECRET_ENV_VAR", "TOTP_MASTER_SECRET")
    TOTP_DIGITS = 6
    TOTP_INTERVAL = 30
    QR_ERROR_CORRECTION = qrcode.ERROR_CORRECT_L

    # Configuración específica del QR
    QR_VERSION = 1
    QR_BOX_SIZE = 2  # Cambiado a 2 para mejor visibilidad
    QR_BORDER = 1
    QR_ERROR_CORRECTION = qrcode.ERROR_CORRECT_L  # Corregida la referencia
    QR_COLORS = {
        'fill': "black",
        'back': "white"
    }
    QR_ERROR_CORRECTION = qrcode.ERROR_CORRECT_L
    TOTP_ALGORITHM = 'SHA1'
def get_banner():
    """Retorna el banner ASCII del programa."""
    return f"""{Fore.CYAN}
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
╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝{Style.RESET_ALL}"""

qr_path = None
qr_expiration_time = None

# Inicializar el registro
extra = {'ip_address': socket.gethostbyname(socket.gethostname()), 'username': getpass.getuser()}
qr_path: Optional[str] = None
qr_expiration_time: Optional[datetime] = None
def get_hidden_input(prompt=""):
    """Obtiene entrada del usuario mostrando asteriscos."""
    if os.name == 'nt':  # Para Windows
        import msvcrt
        print(prompt, end='', flush=True)
        pwd = ""
        while True:
            key = msvcrt.getch()
            key = key.decode('utf-8')
            if key == '\r':  # Enter
                break
            if key == '\b':  # Retroceso
                if len(pwd) > 0:
                    pwd = pwd[:-1]
                    print('\b \b', end='', flush=True)
            else:
                pwd += key
                print('*', end='', flush=True)
        print()
        return pwd
    else:  # Para Unix/Linux
        import termios
        import tty
        print(prompt, end='', flush=True)
        pwd = ""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                char = sys.stdin.read(1)
                if char == '\r' or char == '\n':
                    break
                if char == '\x7f':  # Retroceso
                    if len(pwd) > 0:
                        pwd = pwd[:-1]
                        print('\b \b', end='', flush=True)
                else:
                    pwd += char
                    print('*', end='', flush=True)
        except Exception as e:
            logger.error(f"Error reading input: {str(e)}")
            return ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        print()
        return pwd

def generate_secret():
    """Genera una clave secreta segura compatible con Google Authenticator."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')

def clear_screen():
    """Limpia la pantalla de la terminal."""
    os.system('clear' if os.name == 'posix' else 'cls')

def generar_qr_totp(issuer, account_name, secret=None):
    """Genera y muestra el código QR TOTP."""
    global qr_path, qr_expiration_time
    try:
        if not os.path.exists(Config.QR_DIR):
            os.makedirs(Config.QR_DIR, mode=0o700)

        secret = secret or generate_secret()
        
        # Crear URI TOTP específico para Google Authenticator
        params = {
            'secret': secret,
            'issuer': issuer,
            'algorithm': Config.TOTP_ALGORITHM,
            'digits': str(Config.TOTP_DIGITS),
            'period': str(Config.TOTP_INTERVAL)
        }
        
        uri = f"otpauth://totp/{quote(issuer)}:{quote(account_name)}?{urlencode(params)}"
        
        # Configuración optimizada del QR
        qr = qrcode.QRCode(
            version=Config.QR_VERSION,
            error_correction=Config.QR_ERROR_CORRECTION,
            box_size=2,  # Aumentado a 2 para mejor visibilidad
            border=1
        )
        
        # Añadir datos al QR (faltaba esta línea)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Guardar imagen del QR
        img = qr.make_image(
            fill_color=Config.QR_COLORS['fill'],
            back_color=Config.QR_COLORS['back']
        )
        
        filename = f"qr_{sha256(secret.encode()).hexdigest()[:8]}.png"
        qr_path = os.path.join(Config.QR_DIR, filename)
        
        # Guardar imagen (simplificado para evitar duplicación)
        img.save(qr_path) # type: ignore
        os.chmod(qr_path, 0o600)
        
        qr_expiration_time = datetime.now() + timedelta(seconds=Config.QR_EXPIRATION)

        # Mostrar QR en terminal
        clear_screen()
        print(get_banner())
        
        terminal_width = shutil.get_terminal_size().columns
        matrix = qr.get_matrix()
        qr_width = len(matrix[0]) * 2 + 4
        padding = " " * ((terminal_width - qr_width) // 2)
        
        # Borde superior con título
        title = " CÓDIGO QR PARA GOOGLE AUTHENTICATOR "
        border_width = qr_width - len(title)
        left_border = "═" * (border_width // 2)
        right_border = "═" * (border_width - len(left_border))
        
        print("\n" + padding + Fore.CYAN + f"╔{left_border}{title}{right_border}╗" + Style.RESET_ALL)
        
        # Contenido QR mejorado
        for row in matrix:
            line = ""
            for cell in row:
                if cell:
                    line += "██"
                else:
                    line += "  "
            print(padding + Fore.CYAN + "║ " + Style.RESET_ALL + line + Fore.CYAN + " ║" + Style.RESET_ALL)
        
        # Borde inferior
        print(padding + Fore.CYAN + "╚" + "═" * (qr_width - 2) + "╝" + Style.RESET_ALL + "\n")
        
        return secret, qr_path, uri

    except Exception as e:
        logger.error(f"Error al generar QR: {str(e)}")
        raise

def validar_totp(secret, codigo):
    """Valida el código TOTP."""
    try:
        totp = pyotp.TOTP(
            secret,
            digits=Config.TOTP_DIGITS,
            interval=Config.TOTP_INTERVAL,
            digest=hashlib.sha1
        )
        return totp.verify(codigo)
    except Exception as e:
        logger.error(f"Error al validar TOTP: {str(e)}")
        return False

def show_help():
    """Muestra la ayuda del sistema."""
    clear_screen()
    print(get_banner())
    print(f"""
{Fore.YELLOW}💡 Guía Rápida de Uso{Style.RESET_ALL}

{Fore.CYAN}¿Qué es The Coder Sensei?{Style.RESET_ALL}
Un sistema de autenticación de dos factores (2FA) que genera códigos temporales
para aumentar la seguridad de tu acceso.

{Fore.CYAN}Instrucciones paso a paso:{Style.RESET_ALL}

1️⃣ {Fore.GREEN}Preparación:{Style.RESET_ALL}
   • Descarga Google Authenticator en tu móvil
   • Asegúrate de tener buena iluminación para el QR

2️⃣ {Fore.GREEN}Uso del sistema:{Style.RESET_ALL}
   • Selecciona "Autenticación TOTP"
   • Se mostrará un código QR en pantalla
   • Abre Google Authenticator
   • Pulsa el botón + y elige "Escanear código QR"
   • Apunta la cámara al código QR
   • Verás un código de 6 dígitos en tu móvil

3️⃣ {Fore.GREEN}Verificación:{Style.RESET_ALL}
   • Introduce el código de 6 dígitos mostrado
   • Los códigos cambian cada 30 segundos
   • Tienes {Config.MAX_ATTEMPTS} intentos

{Fore.CYAN}Consejos:{Style.RESET_ALL}
• Si el código no funciona, sincroniza la hora de tu móvil
• El código QR expira en {Config.QR_EXPIRATION} segundos
• Si hay problemas, reinicia el proceso

{Fore.YELLOW}Para más información:{Style.RESET_ALL}
https://github.com/DogSoulDev/The-Coder-Sensei
""")

def authenticate_totp():
    """Proceso de autenticación TOTP."""
    global qr_path
    try:
        clear_screen()
        print(get_banner())
        account_name = getpass.getuser()
        secret, qr_path, uri = generar_qr_totp("TheCoderSensei", account_name)

        print("\n" + Fore.CYAN + "🔐 INSTRUCCIONES:" + Style.RESET_ALL)
        print(Fore.YELLOW + """
1️⃣ Escanea el código QR con Google Authenticator
2️⃣ Espera a que aparezca el código de 6 dígitos
3️⃣ Introduce el código a continuación""" + Style.RESET_ALL)
        
        attempts = 0
        while attempts < Config.MAX_ATTEMPTS:
            if qr_expiration_time and datetime.now() > qr_expiration_time:
                print(Fore.RED + "\n⚠️  El código QR ha expirado. Reinicie el proceso.")
                return False

            if qr_expiration_time:
                tiempo_restante = int((qr_expiration_time - datetime.now()).total_seconds())
                print(Fore.CYAN + "\n⏰ Tiempo restante: " + 
                      str(tiempo_restante) + 
                      " segundos" + Style.RESET_ALL)
            else:
                print(Fore.RED + "\n⚠️  Error: Tiempo de expiración no establecido" + Style.RESET_ALL)
            
            codigo = get_hidden_input("\n🔑 Ingrese el código de verificación (6 dígitos): ")
            if not codigo.isdigit() or len(codigo) != Config.TOTP_DIGITS:
                print(Fore.RED + "\n❌ El código debe tener 6 dígitos numéricos.")
                print(f"🔄 Intentos restantes: {Config.MAX_ATTEMPTS - attempts - 1}")
                attempts += 1
                continue

            if validar_totp(secret, codigo):
                print(Fore.GREEN + "\n✅ ¡Autenticación exitosa!")
                print("🎉 ¡Bienvenido al sistema!")
                return True

            print(Fore.RED + f"\n❌ Código inválido.")
            print(f"🔄 Intentos restantes: {Config.MAX_ATTEMPTS - attempts - 1}")
            attempts += 1
            time.sleep(1)

        print(Fore.RED + "\n🔒 Máximo de intentos alcanzado.")
        print("⚠️  Por seguridad, el proceso se ha bloqueado.")
        return False

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n❌ Proceso cancelado por el usuario.")
        return False
    except Exception as e:
        logger.error(f"Error en autenticación: {str(e)}")
        print(Fore.RED + "\n⚠️  Error en el sistema de autenticación.")
        return False
    finally:
        if qr_path and os.path.exists(qr_path):
            os.remove(qr_path)

def main_menu():
    """Menú principal de la aplicación."""
    while True:
        clear_screen()
        print(get_banner())
        print("\n" + Fore.CYAN + "Opciones disponibles:" + Style.RESET_ALL)
        print(Fore.GREEN + "1." + Style.RESET_ALL + " Autenticación TOTP")
        print(Fore.GREEN + "2." + Style.RESET_ALL + " Ayuda")
        print(Fore.GREEN + "3." + Style.RESET_ALL + " Desarrollador")
        print(Fore.GREEN + "4." + Style.RESET_ALL + " Salir\n")

        choice = input(Fore.CYAN + "➡️  Seleccione una opción: " + Style.RESET_ALL)

        if choice == '1':
            if authenticate_totp():
                print(Fore.GREEN + "\n🚀 Acceso concedido. Ejecutando tareas seguras...")
                time.sleep(2)
            else:
                print(Fore.RED + "\n🔒 Acceso denegado.")
                time.sleep(2)
            print(Fore.YELLOW + "\nPresione 4 para salir o cualquier otra tecla para continuar..." + Style.RESET_ALL)
            if input() == '4':
                print(Fore.YELLOW + "\n👋 Gracias por usar Coder Sensei, Be Water!" + Style.RESET_ALL)
                sys.exit(0)
        elif choice == '2':
            show_help()
            print(Fore.YELLOW + "\nPresione 4 para salir o Enter para continuar..." + Style.RESET_ALL)
            if input() == '4':
                print(Fore.YELLOW + "\n👋 Gracias por usar Coder Sensei, Be Water!" + Style.RESET_ALL)
                sys.exit(0)
        elif choice == '3':
            clear_screen()
            print(get_banner())
            print(f"""
{Fore.CYAN}Desarrollador{Style.RESET_ALL}

¡Hola y gracias por usar The Coder Sensei!

Soy DogSoulDev, para cualquier consulta no dudes en contactar conmigo.
¡Que tengas un buen día!

{Fore.YELLOW}GitHub:{Style.RESET_ALL} https://github.com/DogSoulDev
""")
            print(Fore.YELLOW + "\nPresione 4 para salir o Enter para continuar..." + Style.RESET_ALL)
            if input() == '4':
                print(Fore.YELLOW + "\n👋 Gracias por usar Coder Sensei, Be Water!" + Style.RESET_ALL)
                sys.exit(0)
        elif choice == '4':
            print(Fore.YELLOW + "\n👋 Gracias por usar Coder Sensei, Be Water!" + Style.RESET_ALL)
            sys.exit(0)
        else:
            print(Fore.RED + "\n❌ Opción inválida" + Style.RESET_ALL)
            time.sleep(1)

if __name__ == "__main__":
    try:
        load_dotenv()
        main_menu()
    except Exception as e:
        logger.critical(f"Error crítico: {str(e)}")
        print(Fore.RED + "\n⚠️  Error crítico del sistema. Consulte los logs para más detalles.")
        sys.exit(1)