# ==============================================================================
# Proyecto: NorthStar
# Autor: APNAPDEV
# Repositorio Oficial: https://github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================

# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027
import secrets
import os
import sys
import csv
import stat
import time
import hmac
import hashlib
import getpass
import base64
import io
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.rule import Rule
from rich.align import Align
from rich.padding import Padding
from rich.text import Text



LOGO_ASCII = r"""
  _   _            _   _    ____  _                    
 | \ | | ___  _ __| |_| |__ / ___|| |_ __ _ _ __  __/\__
 |  \| |/ _ \| '__| __| '_ \\___ \| __/ _` | '__| \    /
 | |\  | (_) | |  | |_| | | |___) | || (_| | |    /_  _\
 |_| \_|\___/|_|   \__|_| |_|____/ \__\__,_|_|      \/  

          N O R T H S T A R  ·  v6.1  S E C U R E
"""

console = Console()

# ───────────────────────────────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN DE SEGURIDAD, PUEDES HACER LO QUE QUIERAS, NO TIENE PORQUE AFECTAR A LA LOGÍCA DEL CÓDIGO
# ───────────────────────────────────────────────────────────────────────────────────────────────────────
ARCHIVO_DB        = "claves_seguras.db"
ARCHIVO_HMAC      = "claves_seguras.hmac"
PBKDF2_ITERACIONES = 600_000          # OWASP 2024: mínimo 600,000 para SHA-256
SALT_BYTES        = 32                # 256 bits — margen a futuro
MAX_INTENTOS      = 3                 # Máximo de fallos consecutivos antes de lockout
DELAY_BASE_SEG    = 2                 # Delay base; se duplica con cada fallo (back-off exponencial)
MIN_ENTROPIA_BITS = 40                # Umbral mínimo recomendado para la clave maestra, esto es relativo


# ─────────────────────────────────────────────────────────────────────────────
# UTILIDADES DE SEGURIDAD
# ─────────────────────────────────────────────────────────────────────────────

def leer_clave_segura(prompt_texto: str) -> str:
    """
    Lee la clave maestra con getpass para que NUNCA aparezca en pantalla,
    ni siquiera como asteriscos (evita shoulder-surfing y grabaciones de pantalla).
    """
    try:
        # getpass usa el terminal directamente (no stdout), más seguro que rich
        return getpass.getpass(prompt=f"\n  {prompt_texto}: ")
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[bold red]Operación cancelada por el usuario.[/bold red]")
        sys.exit(0)


def calcular_entropia_shannon(clave: str) -> float:
    """
    Estima la entropía real de la clave en bits usando la fórmula de Shannon.
    No reemplaza un medidor de contraseña profesional, pero detecta claves débiles obvias.
    """
    if not clave:
        return 0.0
    freq = {}
    for c in clave:
        freq[c] = freq.get(c, 0) + 1
    n = len(clave)
    import math
    entropia = -sum((f / n) * math.log2(f / n) for f in freq.values())
    return entropia * n  # entropía total en bits


def evaluar_clave(clave: str) -> tuple[float, str, str]:
    """Devuelve (entropía, nivel, color_rich) para mostrar al usuario."""
    bits = calcular_entropia_shannon(clave)
    if bits < 20:
        return bits, "Muy débil", "bold red"
    if bits < MIN_ENTROPIA_BITS:
        return bits, "Débil", "bold yellow"
    if bits < 80:
        return bits, "Aceptable", "bold green"
    return bits, "Fuerte", "bold bright_green"


def restringir_permisos_archivo(ruta: str):
    try:
        os.chmod(ruta, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass  # Windows: no aplica chmod Unix, pero el archivo sigue siendo funcional


# ─────────────────────────────────────────────────────────────────────────────
# HMAC DE INTEGRIDAD DEL ARCHIVO DE BASE DE DATOS
# ─────────────────────────────────────────────────────────────────────────────

def _hmac_clave_desde_maestra(clave_maestra: str) -> bytes:
    """Deriva una clave de 32 bytes dedicada exclusivamente al HMAC del archivo."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        clave_maestra.encode("utf-8"),
        b"nebula-hmac-salt-v6",   # salt estático solo para el HMAC del archivo
        iterations=50_000,        # menos iteraciones que el cifrado: el HMAC no es el objetivo
        dklen=32,
    )


def firmar_archivo(clave_maestra: str):
    
    if not os.path.exists(ARCHIVO_DB):
        return
    clave_hmac = _hmac_clave_desde_maestra(clave_maestra)
    with open(ARCHIVO_DB, "rb") as f:
        contenido = f.read()
    firma = hmac.new(clave_hmac, contenido, hashlib.sha256).hexdigest()
    with open(ARCHIVO_HMAC, "w", encoding="utf-8") as f:
        f.write(firma)
    restringir_permisos_archivo(ARCHIVO_HMAC)


def verificar_integridad(clave_maestra: str) -> bool:
   
    if not os.path.exists(ARCHIVO_HMAC) or not os.path.exists(ARCHIVO_DB):
        return True 
    clave_hmac = _hmac_clave_desde_maestra(clave_maestra)
    with open(ARCHIVO_DB, "rb") as f:
        contenido = f.read()
    firma_esperada = hmac.new(clave_hmac, contenido, hashlib.sha256).hexdigest()
    with open(ARCHIVO_HMAC, "r", encoding="utf-8") as f:
        firma_guardada = f.read().strip()

    return hmac.compare_digest(firma_esperada, firma_guardada)

# NorthStar es mi programa más querido despues de TERmita ya que con el empece a programar
# Gracias por usar o simpplemente leer este código
# ─────────────────────────────────────────────────────────────────────────────
# EL CORE CRIPTOGRÁFICO
# ─────────────────────────────────────────────────────────────────────────────

def generar_llave_segura(clave_maestra: str, salt: bytes) -> bytes:
    """
    Deriva una clave Fernet (AES-128-CBC + HMAC-SHA256) con PBKDF2-SHA256.
    600,000 iteraciones según OWASP 2024 para SHA-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERACIONES,
    )
    return base64.urlsafe_b64encode(kdf.derive(clave_maestra.encode("utf-8")))


def encriptar_nebula(texto: str, clave: str) -> str:
    """
    Genera salt único de 32 bytes, deriva la clave y cifra con Fernet.
    Empaqueta [salt(32)] + [datos_cifrados] y devuelve en hexadecimal.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    llave = generar_llave_segura(clave, salt)
    f = Fernet(llave)
    datos_cifrados = f.encrypt(texto.encode("utf-8"))
    return (salt + datos_cifrados).hex()


def descifrar_nebula(texto_hex: str, clave: str, intentos_fallidos: list) -> str:
    """
    Desempaqueta el bloque hex, extrae el salt y descifra.
    Aplica delay exponencial por cada fallo para frustrar ataques de fuerza bruta.
    Lanza InvalidToken si la clave es incorrecta (tras el delay).
    """
    try:
        todo_junto = bytes.fromhex(texto_hex)
    except ValueError:
        raise ValueError("Formato hexadecimal inválido.")

    salt             = todo_junto[:SALT_BYTES]
    datos_encriptados = todo_junto[SALT_BYTES:]

    llave = generar_llave_segura(clave, salt)
    f = Fernet(llave)

    try:
        datos = f.decrypt(datos_encriptados)
        intentos_fallidos.clear()  # Éxito: reiniciamos el contador para o saturar variables más adelante
        return datos.decode("utf-8")
    except InvalidToken:
        # Delay exponencial: 2s, 4s, 8s... antes de informar del error ya que sino podemo sufrir de fuerza bruta
        intentos_fallidos.append(1)
        n = len(intentos_fallidos)
        delay = DELAY_BASE_SEG * (2 ** (n - 1))
        console.print(f"\n[dim]Verificando... espera {delay}s[/dim]")
        time.sleep(delay)
        raise


# ─────────────────────────────────────────────────────────────────────────────
# GESTOR DE CREDENCIALES    Usamos un CSV seguro con HMAC de integridad
# ─────────────────────────────────────────────────────────────────────────────

def guardar_en_archivo(sitio: str, usuario: str, password_cifrada: str):
    """
    Guarda una nueva entrada usando el módulo csv con quoting completo.
    Soporta cualquier carácter en sitio/usuario"""

    archivo_nuevo = not os.path.exists(ARCHIVO_DB)
    with open(ARCHIVO_DB, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow([sitio, usuario, password_cifrada])
    if archivo_nuevo:
        restringir_permisos_archivo(ARCHIVO_DB)


def leer_archivo() -> list:
   
    if not os.path.exists(ARCHIVO_DB):
        return []
    credenciales = []
    with open(ARCHIVO_DB, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f, quoting=csv.QUOTE_ALL)
        for fila in reader:
            if len(fila) == 3:
                credenciales.append({"sitio": fila[0], "usuario": fila[1], "password": fila[2]})
    return credenciales


def _verificar_intentos(intentos: list):
  
    if len(intentos) >= MAX_INTENTOS:
        console.print(Panel(
            f"[bold red]✖ Demasiados intentos fallidos ({MAX_INTENTOS}/{MAX_INTENTOS}).\n"
            "Por seguridad, esta sesión ha sido bloqueada.\n"
            "Reinicia el programa para intentarlo de nuevo.[/bold red]",
            title="🔒 Sesión bloqueada",
            border_style="red",
            expand=False,
        ))
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  SUBMENÚ GESTOR DE CONTRASEÑAS
# ─────────────────────────────────────────────────────────────────────────────
def _cabecera(titulo: str, subtitulo: str = "") -> None:
   
    console.clear()
    console.print(LOGO_ASCII, style="bold cyan", justify="center")
    console.print(Rule(style="bright_magenta"))
    console.print(Align.center(f"[bold white]{titulo}[/bold white]"))
    if subtitulo:
        console.print(Align.center(f"[dim]{subtitulo}[/dim]"))
    console.print(Rule(style="bright_magenta"))
    console.print()
 
 
def _menu_opciones(opciones: list[tuple[str, str, str]]):
    for tecla, icono, desc in opciones:
        if tecla.upper() == "Q" or tecla == "4" or tecla == "3" and icono == "✖":
            console.print(f"  [bold red][ {tecla} ][/bold red]  {icono}  [dim]{desc}[/dim]")
        else:
            console.print(f"  [bold cyan][ {tecla} ][/bold cyan]  {icono}  [white]{desc}[/white]")
    console.print()
 
 
def _ok(msg: str):
    console.print(f"\n  [bold green]✔[/bold green]  {msg}")
 
 
def _err(msg: str):
    console.print(f"\n  [bold red]✖[/bold red]  {msg}")
 
 
def _warn(msg: str):
    console.print(f"\n  [bold yellow]⚠[/bold yellow]  {msg}")
 
 
def _pausa():
    console.print()
    console.input("  [dim]Pulsa ENTER para continuar...[/dim]")
 
 
def _barra_entropia(bits: float) -> str:
    """Devuelve una barra visual de 10 bloques proporcional a la entropía (máx 120 bits)."""
    llenos = min(10, int((bits / 120) * 10))
    vacios = 10 - llenos
    if bits < 20:
        color = "red"
    elif bits < 40:
        color = "yellow"
    elif bits < 80:
        color = "green"
    else:
        color = "bright_green"
    return f"[{color}]{'█' * llenos}{'░' * vacios}[/{color}]  [{color}]{bits:.0f} bits[/{color}]"
 
 
def _pantalla_bienvenida():
    console.clear()
    console.print(LOGO_ASCII, style="bold cyan", justify="center")
    console.print(Rule(style="bright_magenta"))
    console.print(Align.center("[bold white]Bienvenido — Primera ejecución[/bold white]"))
    console.print(Rule(style="bright_magenta"))
    console.print()
 
    console.print(Panel(
        "[bold white]¿Qué es la clave maestra?[/bold white]\n\n"
        "Es la única contraseña que debes memorizar. Todas tus credenciales\n"
        "se cifran individualmente usando ella. Si la pierdes, [bold red]no hay\n"
        "recuperación posible[/bold red]: los datos cifrados son irrecuperables.\n\n"
        "[bold white]Recomendaciones:[/bold white]\n"
        "  ·  Usa una frase larga y memorable, no una palabra sola\n"
        "  ·  Combina mayúsculas, símbolos y números\n"
        "  ·  Mínimo 12 caracteres — cuanto más larga, más segura\n"
        "  ·  Ejemplo fuerte: [italic]\"Cafe!ConLeche_3Tazas#2024\"[/italic]\n\n"
        "[dim]Este aviso solo aparece una vez.[/dim]",
        border_style="bright_magenta",
        padding=(1, 3),
    ))
    console.print()
    console.input("  [dim]Pulsa ENTER para empezar...[/dim]")



def submenu_gestor():
    intentos_fallidos = []
 
    while True:
        console.clear()
        console.print(LOGO_ASCII, style="bold cyan")
        console.print(Panel("[bold yellow]🗄️ Gestor Seguro de Contraseñas[/bold yellow]", border_style="yellow", expand=False))
        console.print("[bold green][1][/bold green] Ver mis cuentas guardadas")
        console.print("[bold green][2][/bold green] Registrar nueva contraseña")
        console.print("[bold red][3][/bold red] Volver al menú principal\n")
 
        sub_opt = Prompt.ask("Selecciona una opción", choices=["1", "2", "3"])
 
        # ── VER CUENTAS ──────────────────────────────────────────────────────
        if sub_opt == "1":
            cuentas = leer_archivo()
            if not cuentas:
                console.print("\n[bold red]✖ No hay ninguna contraseña guardada todavía.[/bold red]")
                console.input("\n[dim]Presiona ENTER para continuar...[/dim]")
                continue
 
            tabla = Table(title="🔒 Tus Credenciales Protegidas", header_style="bold magenta")
            tabla.add_column("ID", justify="center", style="cyan")
            tabla.add_column("Sitio / Aplicación", style="white")
            tabla.add_column("Usuario / Correo", style="green")
            tabla.add_column("Contraseña", style="yellow")
 
            for index, cuenta in enumerate(cuentas):
                tabla.add_row(str(index + 1), cuenta["sitio"], cuenta["usuario"], "********")
 
            console.print("\n", tabla)
 
            revelar = Prompt.ask("\n¿Quieres revelar alguna contraseña? (Introduce el ID o 'N' para no)", default="N")
 
            if revelar.upper() != "N" and revelar.isdigit():
                id_elegido = int(revelar) - 1
                if 0 <= id_elegido < len(cuentas):
                    _verificar_intentos(intentos_fallidos)
                    clave_maestra = leer_clave_segura("Introduce tu clave maestra para desencriptar (oculta)")
                    with console.status("[bold]Derivando llave y descifrando bloque...[/bold]"):
                        try:
                            password_real = descifrar_nebula(cuentas[id_elegido]["password"], clave_maestra, intentos_fallidos)
                            console.print(Panel(
                                f"[bold green]Sitio:[/bold green] {cuentas[id_elegido]['sitio']}\n"
                                f"[bold green]Usuario:[/bold green] {cuentas[id_elegido]['usuario']}\n"
                                f"[bold bright_red]Contraseña:[/bold bright_red] [bold white]{password_real}[/bold white]",
                                title="🔓 Credencial Revelada", border_style="red", expand=False
                            ))
                        except (ValueError, UnicodeDecodeError, InvalidToken):
                            console.print(
                                f"\n[bold red]✖ Clave incorrecta o datos corruptos. "
                                f"Intento {len(intentos_fallidos)}/{MAX_INTENTOS}.[/bold red]"
                            )
                else:
                    console.print("\n[bold red]✖ ID no válido.[/bold red]")
 
            console.input("\n[dim]Presiona ENTER para continuar...[/dim]")
 
        # ── REGISTRAR NUEVA ──────────────────────────────────────────────────
        elif sub_opt == "2":
            console.print("\n[bold yellow]--- REGISTRAR CUENTA ---[/bold yellow]")
            sitio          = console.input("[bold white]Aplicación o Web (ej: Netflix, Gmail):[/bold white] ").strip()
            usuario        = console.input("[bold white]Usuario o Correo electrónico:[/bold white] ").strip()
            password_plana = leer_clave_segura("Contraseña a guardar (oculta)")
            clave_maestra  = leer_clave_segura("Clave maestra para encriptar (oculta, no la olvides)")
 
            if not sitio or not usuario or not password_plana or not clave_maestra:
                console.print("\n[bold red]✖ Error: Todos los campos son obligatorios.[/bold red]")
            else:
                bits, nivel, color = evaluar_clave(clave_maestra)
                console.print(f"\n  Fortaleza de clave: [{color}]{nivel} (~{bits:.0f} bits)[/{color}]")
                if bits < MIN_ENTROPIA_BITS:
                    console.print(
                        "  [bold yellow]⚠ Clave maestra débil. "
                        "Considera una frase de paso más larga y variada.[/bold yellow]"
                    )
 
                with console.status(f"[bold]Ejecutando {PBKDF2_ITERACIONES:,} iteraciones SHA-256...[/bold]"):
                    password_cifrada = encriptar_nebula(password_plana, clave_maestra)
                    guardar_en_archivo(sitio, usuario, password_cifrada)
                    firmar_archivo(clave_maestra)
 
                console.print("\n[bold green]✔ ¡Cuenta guardada y encriptada exitosamente![/bold green]")
 
            console.input("\n[dim]Presiona ENTER para continuar...[/dim]")
 
        elif sub_opt == "3":
            break

def _cabecera(titulo: str, subtitulo: str = ""):
    
    console.clear()
    console.print(LOGO_ASCII, style="bold cyan", justify="center")
    console.print(Rule(style="bright_magenta"))
    console.print(Align.center(f"[bold white]{titulo}[/bold white]"))
    if subtitulo:
        console.print(Align.center(f"[dim]{subtitulo}[/dim]"))
    console.print(Rule(style="bright_magenta"))
    console.print()
 
 
def _menu_opciones(opciones: list[tuple[str, str, str]]):
    for tecla, icono, desc in opciones:
        if tecla.upper() == "Q" or tecla == "4" or tecla == "3" and icono == "✖":
            console.print(f"  [bold red][ {tecla} ][/bold red]  {icono}  [dim]{desc}[/dim]")
        else:
            console.print(f"  [bold cyan][ {tecla} ][/bold cyan]  {icono}  [white]{desc}[/white]")
    console.print()
 
 
def _ok(msg: str):
    console.print(f"\n  [bold green]✔[/bold green]  {msg}")
 
def _err(msg: str):
    console.print(f"\n  [bold red]✖[/bold red]  {msg}")
 
def _warn(msg: str):
    console.print(f"\n  [bold yellow]⚠[/bold yellow]  {msg}")
 
def _pausa():
    console.print()
    console.input("  [dim]Pulsa ENTER para continuar...[/dim]")
 
 
def _barra_entropia(bits: float) -> str:
    """Devuelve una barra visual de 10 bloques proporcional a la entropía (máx 120 bits)."""
    llenos = min(10, int((bits / 120) * 10))
    vacios = 10 - llenos
    if bits < 20:
        color = "red"
    elif bits < 40:
        color = "yellow"
    elif bits < 80:
        color = "green"
    else:
        color = "bright_green"
    return f"[{color}]{'█' * llenos}{'░' * vacios}[/{color}]  [{color}]{bits:.0f} bits[/{color}]"
 
 
def _pantalla_bienvenida():
   
    console.clear()
    console.print(LOGO_ASCII, style="bold cyan", justify="center")
    console.print(Rule(style="bright_magenta"))
    console.print(Align.center("[bold white]Bienvenido — Primera ejecución[/bold white]"))
    console.print(Rule(style="bright_magenta"))
    console.print()
 
    console.print(Panel(
        "[bold white]¿Qué es la clave maestra?[/bold white]\n\n"
        "Es la única contraseña que debes memorizar. Todas tus credenciales\n"
        "se cifran individualmente usando ella. Si la pierdes, [bold red]no hay\n"
        "recuperación posible[/bold red]: los datos cifrados son irrecuperables.\n\n"
        "[bold white]Recomendaciones:[/bold white]\n"
        "  ·  Usa una frase larga y memorable, no una palabra sola\n"
        "  ·  Combina mayúsculas, símbolos y números\n"
        "  ·  Mínimo 12 caracteres — cuanto más larga, más segura\n"
        "  ·  Ejemplo fuerte: [italic]\"Cafe!ConLeche_3Tazas#2024\"[/italic]\n\n"
        "[dim]Este aviso solo aparece una vez.[/dim]",
        border_style="bright_magenta",
        padding=(1, 3),
    ))
    console.print()
    console.input("  [dim]Pulsa ENTER para empezar...[/dim]")
# ────────────────────────────────────────────────────────────────────────────────────────────
# MENÚ PRINCIPAL LO PODÉIS ADAPTAR A VUESTRO ESTILO PERO OJO CON LOS MENSAJES Y LAS VARIABLES
# ────────────────────────────────────────────────────────────────────────────────────────────


def _pantalla_bienvenida():
    
    console.clear()
    console.print(Panel(
        "[bold yellow]⚠  Primera ejecución — Lee esto antes de continuar[/bold yellow]",
        border_style="yellow", expand=False
    ))
    console.print(Panel(
        "[bold white]¿Qué es la clave maestra?[/bold white]\n\n"
        "Es la única contraseña que debes memorizar.\n"
        "Todas tus credenciales se cifran usando ella.\n\n"
        "[bold red]Si la pierdes, no hay recuperación posible.[/bold red]\n"
        "Los datos cifrados serán irrecuperables para siempre.\n\n"
        "[bold white]Recomendaciones:[/bold white]\n"
        "  · Usa una frase larga y memorable, no una sola palabra\n"
        "  · Combina mayúsculas, símbolos y números\n"
        "  · Mínimo 12 caracteres\n"
        '  · Ejemplo: "Cafe!ConLeche_3Tazas#2024"\n\n'
        "[dim]Este aviso solo aparece una vez.[/dim]",
        border_style="bright_magenta", expand=False
    ))
    console.input("\n[dim]Presiona ENTER para empezar...[/dim]")
 
 
def nebula_cipher_menu():
    intentos_fallidos = []
 
   
    if not os.path.exists(ARCHIVO_DB):
        _pantalla_bienvenida()
 
    while True:
        console.clear()
        console.print(LOGO_ASCII, style="bold cyan")
        console.print(Panel(
            "[bold cyan]🌌 NEBULA-NORTHSTAR v6.1[/bold cyan]\n"
            "[dim]PBKDF2-SHA256 · 600,000 iter · AES-128-CBC+HMAC · Salt 256-bit · Fernet[/dim]",
            border_style="bright_magenta", expand=False
        ))
 
        console.print("[bold green][1][/bold green] Encriptar texto plano")
        console.print("[bold green][2][/bold green] Desencriptar código hexadecimal")
        console.print("[bold green][3][/bold green] 🗄️  Acceder al Gestor de Contraseñas")
        console.print("[bold red][4][/bold red] Salir del programa\n")
 
        opt = Prompt.ask("Selecciona una opción", choices=["1", "2", "3", "4"])
 
        # ── ENCRIPTAR ────────────────────────────────────────────────────────
        if opt == "1":
            console.print("\n[bold yellow]--- ENCRIPTACIÓN ---[/bold yellow]")
            texto = console.input("[bold white]Texto a proteger:[/bold white] ").strip()
            clave = leer_clave_segura("Clave secreta (oculta, no la olvides)")
 
            if not texto or not clave:
                console.print("\n[bold red]✖ Error: El texto y la clave no pueden estar vacíos.[/bold red]")
            else:
                bits, nivel, color = evaluar_clave(clave)
                console.print(f"\n  Fortaleza de clave: [{color}]{nivel} (~{bits:.0f} bits)[/{color}]")
 
                with console.status(f"[bold]Calculando {PBKDF2_ITERACIONES:,} iteraciones...[/bold]"):
                    res = encriptar_nebula(texto, clave)
 
                
                console.print("\n", Panel(
                    "[bold green] El texto ha sido encriptado bajo el protocolo v6.1 Secure[/bold green]",
                    title="Proceso Completado!!!", border_style="green", expand=False
                ))
                
                
                try:
                    import tkinter as tk
                    r = tk.Tk()
                    r.withdraw()
                    r.clipboard_clear()
                    r.clipboard_append(res)
                    r.update()
                    r.destroy()
                    aviso_copiado = "[bold green](¡Copiado automáticamente al portapapeles!)[/bold green]"
                except Exception:
                    aviso_copiado = ""

                
                console.print(f"\n  [bold white]📋 CÓDIGO HEXADECIMAL {aviso_copiado}:[/bold white]")
                console.print(f"  [bold yellow]{res}[/bold yellow]\n")
 
            console.input("\n[dim]Presiona ENTER para continuar...[/dim]")
 
        # ── DESENCRIPTAR ─────────────────────────────────────────────────────
        elif opt == "2":
            _verificar_intentos(intentos_fallidos)
 
            console.print("\n[bold yellow]--- DESENCRIPTACIÓN ---[/bold yellow]")
            texto_hex = console.input("[bold white]Código Hexadecimal:[/bold white] ").strip()
            clave     = leer_clave_segura("Clave secreta (oculta)")
 
            try:
                with console.status("[bold]Rompiendo iteraciones de seguridad...[/bold]"):
                    res = descifrar_nebula(texto_hex, clave, intentos_fallidos)
 
                console.print("\n", Panel(
                    f"[bold green]Mensaje Original Recuperado:[/bold green]\n[white]{res}[/white]",
                    title="Desencriptado", border_style="green", expand=False
                ))
            except ValueError:
                console.print("\n[bold red]✖ Error: El código introducido no es un formato Hexadecimal válido.[/bold red]")
            except (UnicodeDecodeError, InvalidToken):
                console.print(
                    f"\n[bold red]✖ Error: Clave incorrecta o datos corruptos. "
                    f"Intento {len(intentos_fallidos)}/{MAX_INTENTOS}.[/bold red]"
                )
 
            console.input("\n[dim]Presiona ENTER para continuar...[/dim]")
 
        elif opt == "3":
            submenu_gestor()
 
        elif opt == "4":
            console.print("\n[bold cyan]¡Hasta la próxima! Cerrando sistema Nebula... 🚀[/bold cyan]\n")
            break


if __name__ == "__main__":
    nebula_cipher_menu()