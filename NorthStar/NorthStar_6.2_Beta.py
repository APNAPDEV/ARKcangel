# ==============================================================================
# Proyecto: NorthStar 6.2
# Autor: APNAPDEV
# Repositorio Oficial: https://github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================

# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027

# Dependencias:  pip install cryptography rich pyperclip
# (En Linux, pyperclip necesita xclip, xsel o wl-clipboard instalado.)


# NOTA: NorthStar 6.2 Beta es la primera versión de NorthStar en la que se ha
# usado IA: parte de la versión 6.1 final, revisada y mejorada con ayuda de IA.
# Esta app es muy especial para mi

import atexit
import base64
import csv
import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import stat
import sys
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    import pyperclip
except ImportError:  # La app sigue funcionando sin portapapeles
    pyperclip = None


LOGO_ASCII = r"""
  _   _            _   _    ____  _                    
 | \ | | ___  _ __| |_| |__ / ___|| |_ __ _ _ __  __/\__
 |  \| |/ _ \| '__| __| '_ \\___ \| __/ _` | '__| \    /
 | |\  | (_) | |  | |_| | | |___) | || (_| | |    /_  _\
 |_| \_|\___/|_|   \__|_| |_|____/ \__\__,_|_|      \/  

          N O R T H S T A R  ·  v6.2 Beta  S E C U R E
"""

console = Console()

# ───────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN SUPERFICIAL PARA LOS OPERADORES
# ───────────────────────────────────────────────────────────────────────────────
BASE_DIR            = Path(__file__).resolve().parent
ARCHIVO_BOVEDA      = BASE_DIR / "northstar.vault"
ARCHIVO_DB_LEGACY   = BASE_DIR / "claves_seguras.db"     # formato antiguo (CSV)
ARCHIVO_HMAC_LEGACY = BASE_DIR / "claves_seguras.hmac"   # formato antiguo

PBKDF2_ITERACIONES  = 600_000      # OWASP 2024 para PBKDF2-HMAC-SHA256
ITER_MIN, ITER_MAX  = 100_000, 10_000_000   # Rango aceptado al leer la cabecera
SALT_BYTES          = 32
MIN_ENTROPIA_BITS   = 40
MAX_REINTENTOS_UI   = 3            # Solo comodidad de UX, NO es una medida de seguridad
PORTAPAPELES_SEG    = 30           # Segundos hasta borrar el portapapeles
PADDING_BYTES       = 4096         # El JSON se rellena a múltiplos de este tamaño

MAGIC               = b"NSVLT1"    # Cabecera: MAGIC(6) + iteraciones(4) + salt(32)
LEN_CABECERA        = len(MAGIC) + 4 + SALT_BYTES


# ───────────────────────────────────────────────────────────────────────────────
# UTILIDADES DE INTERFAZ
# ───────────────────────────────────────────────────────────────────────────────
def _cabecera(titulo: str, subtitulo: str = "") -> None:
    console.clear()
    # Align.center sobre el bloque entero mantiene la forma del logo;
    # justify="center" centraría cada línea por separado y lo descompondría.
    console.print(Align.center(Text(LOGO_ASCII.strip("\n"), style="bold cyan")))
    console.print(Rule(style="bright_magenta"))
    console.print(Align.center(f"[bold white]{titulo}[/bold white]"))
    if subtitulo:
        console.print(Align.center(f"[dim]{subtitulo}[/dim]"))
    console.print(Rule(style="bright_magenta"))
    console.print()


def _ok(msg: str) -> None:
    console.print(f"\n  [bold green]✔[/bold green]  {msg}")


def _err(msg: str) -> None:
    console.print(f"\n  [bold red]✖[/bold red]  {msg}")


def _warn(msg: str) -> None:
    console.print(f"\n  [bold yellow]⚠[/bold yellow]  {msg}")


def _pausa() -> None:
    console.print()
    console.input("  [dim]Pulsa ENTER para continuar...[/dim]")


def _barra_entropia(bits: float) -> str:
    """Barra visual de 10 bloques proporcional a la entropía (máx 120 bits)."""
    llenos = min(10, int((bits / 120) * 10))
    vacios = 10 - llenos
    if bits < 20:
        color = "red"
    elif bits < MIN_ENTROPIA_BITS:
        color = "yellow"
    elif bits < 80:
        color = "green"
    else:
        color = "bright_green"
    return f"[{color}]{'█' * llenos}{'░' * vacios}[/{color}]  [{color}]{bits:.0f} bits[/{color}]"


def _pantalla_bienvenida() -> None:
    console.clear()
    console.print(Panel(
        "[bold yellow]⚠  Primera ejecución — Lee esto antes de continuar[/bold yellow]",
        border_style="yellow", expand=False
    ))
    console.print(Panel(
        "[bold white]¿Qué es la clave maestra?[/bold white]\n\n"
        "Es la única contraseña que debes memorizar.\n"
        "Toda tu bóveda (sitios, usuarios y contraseñas) se cifra con ella.\n\n"
        "[bold red]Si la pierdes, no hay recuperación posible.[/bold red]\n"
        "Los datos cifrados serán irrecuperables para siempre.\n"
        "Por eso se te pedirá escribirla dos veces.\n\n"
        "[bold white]Recomendaciones:[/bold white]\n"
        "  · Usa una frase larga y memorable, no una sola palabra\n"
        "  · Combina mayúsculas, símbolos y números\n"
        "  · Mínimo 12 caracteres\n"
        '  · Ejemplo: "Cafe!ConLeche_3Tazas#2024"\n\n'
        "[dim]Este aviso solo aparece una vez.[/dim]",
        border_style="bright_magenta", expand=False
    ))
    console.input("\n[dim]Presiona ENTER para empezar...[/dim]")


# ───────────────────────────────────────────────────────────────────────────────
# ENTRADA SEGURA DE CLAVES Y EVALUACIÓN DE FORTALEZA
# ───────────────────────────────────────────────────────────────────────────────
def leer_clave_segura(prompt_texto: str) -> str:
    """Lee una clave con getpass: nunca se muestra en pantalla."""
    try:
        return getpass.getpass(prompt=f"\n  {prompt_texto}: ")
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[bold red]Operación cancelada por el usuario.[/bold red]")
        sys.exit(0)


def leer_clave_confirmada(prompt_texto: str) -> str | None:
    """Pide la clave dos veces. Devuelve None (y avisa) si no coinciden o está vacía."""
    c1 = leer_clave_segura(prompt_texto)
    if not c1:
        _err("La clave no puede estar vacía. Operación abortada.")
        return None
    c2 = leer_clave_segura("Repite la clave para confirmar")
    if not hmac.compare_digest(c1.encode("utf-8"), c2.encode("utf-8")):
        _err("Las claves no coinciden. Operación abortada (no se ha guardado nada).")
        return None
    return c1


def estimar_entropia(clave: str) -> float:
    """
    Estimación CONSERVADORA en bits: el mínimo entre (a) longitud × log2(tamaño
    del alfabeto usado) y (b) la entropía de Shannon empírica × longitud, que
    penaliza repeticiones. Claves de <12 caracteres se limitan a "Débil".
    Es una heurística, no sustituye a un medidor como zxcvbn.
    """
    if not clave:
        return 0.0
    n = len(clave)
    pool = 0
    if any(c.islower() for c in clave):
        pool += 26
    if any(c.isupper() for c in clave):
        pool += 26
    if any(c.isdigit() for c in clave):
        pool += 10
    if any(not c.isalnum() for c in clave):
        pool += 33
    cota_alfabeto = n * math.log2(pool) if pool else 0.0
    shannon = -sum((f / n) * math.log2(f / n) for f in Counter(clave).values()) * n
    bits = min(cota_alfabeto, shannon)
    if n < 12:
        bits = min(bits, MIN_ENTROPIA_BITS - 1)
    return bits


def evaluar_clave(clave: str) -> tuple[float, str, str]:
    """Devuelve (entropía, nivel, color_rich)."""
    bits = estimar_entropia(clave)
    if bits < 20:
        return bits, "Muy débil", "bold red"
    if bits < MIN_ENTROPIA_BITS:
        return bits, "Débil", "bold yellow"
    if bits < 80:
        return bits, "Aceptable", "bold green"
    return bits, "Fuerte", "bold bright_green"


def mostrar_fortaleza(clave: str) -> float:
    bits, nivel, color = evaluar_clave(clave)
    console.print(f"\n  Fortaleza: [{color}]{nivel}[/{color}]  {_barra_entropia(bits)}")
    return bits


# ───────────────────────────────────────────────────────────────────────────────
# PORTAPAPELES SEGURO (pyperclip + borrado automático)
# ───────────────────────────────────────────────────────────────────────────────
_clip_lock = threading.Lock()
_clip_timer: threading.Timer | None = None
_clip_valor: str | None = None


def _limpiar_portapapeles() -> None:
    """Borra el portapapeles solo si aún contiene lo que copiamos nosotros."""
    global _clip_timer, _clip_valor
    with _clip_lock:
        if _clip_valor is not None and pyperclip is not None:
            try:
                if pyperclip.paste() == _clip_valor:
                    pyperclip.copy("")
            except Exception:
                pass
        _clip_valor = None
        _clip_timer = None


def copiar_seguro(texto: str, autoborrar: bool = True) -> bool:
    """Copia al portapapeles y, si autoborrar, lo limpia tras PORTAPAPELES_SEG segundos."""
    global _clip_timer, _clip_valor
    if pyperclip is None:
        return False
    try:
        pyperclip.copy(texto)
    except Exception:  # PyperclipException, sin xclip/xsel, entorno headless...
        return False
    if autoborrar:
        with _clip_lock:
            if _clip_timer is not None:
                _clip_timer.cancel()
            _clip_valor = texto
            _clip_timer = threading.Timer(PORTAPAPELES_SEG, _limpiar_portapapeles)
            _clip_timer.daemon = True
            _clip_timer.start()
    return True


def _limpiar_al_salir() -> None:
    """Si el programa termina antes de los 30 s, limpia de inmediato."""
    if _clip_timer is not None:
        _clip_timer.cancel()
    _limpiar_portapapeles()


atexit.register(_limpiar_al_salir)


# ───────────────────────────────────────────────────────────────────────────────
# CORE CRIPTOGRÁFICO
# ───────────────────────────────────────────────────────────────────────────────
def restringir_permisos_archivo(ruta) -> None:
    try:
        os.chmod(ruta, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass  # Windows: chmod Unix no aplica


def generar_llave_segura(clave_maestra: str, salt: bytes,
                         iteraciones: int = PBKDF2_ITERACIONES) -> bytes:
    """Deriva una clave Fernet (AES-128-CBC + HMAC-SHA256) con PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iteraciones,
    )
    return base64.urlsafe_b64encode(kdf.derive(clave_maestra.encode("utf-8")))


def encriptar_nebula(texto: str, clave: str) -> str:
    """Cifrado de texto suelto: [salt(32)] + [token Fernet] en hexadecimal."""
    salt = secrets.token_bytes(SALT_BYTES)
    f = Fernet(generar_llave_segura(clave, salt))
    return (salt + f.encrypt(texto.encode("utf-8"))).hex()


def descifrar_nebula(texto_hex: str, clave: str, iteraciones: int = PBKDF2_ITERACIONES) -> str:
    """
    Descifra un bloque hex. Lanza ValueError (formato) o InvalidToken (clave
    incorrecta / datos manipulados). El coste del KDF es la defensa contra fuerza bruta.
    """
    try:
        todo = bytes.fromhex(texto_hex)
    except ValueError:
        raise ValueError("Formato hexadecimal inválido.")
    if len(todo) <= SALT_BYTES:
        raise ValueError("Bloque demasiado corto.")
    salt, datos = todo[:SALT_BYTES], todo[SALT_BYTES:]
    f = Fernet(generar_llave_segura(clave, salt, iteraciones))
    return f.decrypt(datos).decode("utf-8")


# ───────────────────────────────────────────────────────────────────────────────
# BÓVEDA CIFRADA COMPLETA (un único bloque binario)
# ───────────────────────────────────────────────────────────────────────────────
class BovedaError(Exception):
    """Error genérico de bóveda (formato, E/S)."""


class ClaveIncorrectaError(BovedaError):
    """Clave maestra incorrecta O archivo manipulado/corrupto (indistinguibles)."""


def _escritura_atomica(ruta: Path, datos: bytes) -> None:
    """Escribe a un temporal (0600), fsync y os.replace: nunca deja una bóveda a medias."""
    if ruta.exists():
        try:
            shutil.copy2(ruta, Path(str(ruta) + ".bak"))
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(dir=str(ruta.parent), prefix=".ns_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(datos)
            f.flush()
            os.fsync(f.fileno())
        restringir_permisos_archivo(tmp)
        os.replace(tmp, ruta)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Boveda:
    """
    Archivo: MAGIC | iteraciones(4) | salt(32) | token Fernet(JSON completo).

    Integridad: Fernet autentica el token con HMAC-SHA256 y lo verifica ANTES de
    descifrar. Si el archivo (o el salt/iteraciones de la cabecera) se altera, la
    apertura falla con ClaveIncorrectaError. Por eso ya no hace falta un .hmac aparte.
    La clave maestra en texto no se conserva: en sesión solo queda el objeto Fernet.
    """

    def __init__(self, llave: bytes, salt: bytes, iteraciones: int, entradas: list):
        self._fernet = Fernet(llave)
        self._salt = salt
        self._iteraciones = iteraciones
        self.entradas: list[dict] = entradas

    @classmethod
    def crear(cls, clave: str, entradas: list | None = None) -> "Boveda":
        salt = secrets.token_bytes(SALT_BYTES)
        llave = generar_llave_segura(clave, salt, PBKDF2_ITERACIONES)
        b = cls(llave, salt, PBKDF2_ITERACIONES, entradas or [])
        b.guardar()
        return b

    @classmethod
    def abrir(cls, clave: str) -> "Boveda":
        try:
            blob = ARCHIVO_BOVEDA.read_bytes()
        except OSError as e:
            raise BovedaError(f"No se pudo leer la bóveda: {e}")

        if len(blob) <= LEN_CABECERA or not blob.startswith(MAGIC):
            raise BovedaError("El archivo no es una bóveda NorthStar válida (o está corrupto).")

        iteraciones = int.from_bytes(blob[len(MAGIC):len(MAGIC) + 4], "big")
        if not (ITER_MIN <= iteraciones <= ITER_MAX):
            raise BovedaError("Cabecera de bóveda inválida (posible manipulación).")
        salt = blob[len(MAGIC) + 4:LEN_CABECERA]
        token = blob[LEN_CABECERA:]

        llave = generar_llave_segura(clave, salt, iteraciones)
        fernet = Fernet(llave)
        try:
            plano = fernet.decrypt(token)   # verifica HMAC antes de descifrar
        except InvalidToken:
            raise ClaveIncorrectaError(
                "Clave maestra incorrecta, o la bóveda ha sido manipulada/corrompida."
            )

        try:
            datos = json.loads(plano.decode("utf-8"))
            entradas = datos["entradas"]
            if not isinstance(entradas, list):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            raise BovedaError("El contenido descifrado tiene un formato inesperado.")

        return cls(llave, salt, iteraciones, entradas)

    def guardar(self) -> None:
        plano = json.dumps(
            {"version": 1, "entradas": self.entradas}, ensure_ascii=False
        ).encode("utf-8")
        # Relleno con espacios (JSON los ignora) para ocultar el nº aproximado de entradas
        plano += b" " * (-len(plano) % PADDING_BYTES)
        token = self._fernet.encrypt(plano)   # IV aleatorio nuevo en cada guardado
        blob = MAGIC + self._iteraciones.to_bytes(4, "big") + self._salt + token
        _escritura_atomica(ARCHIVO_BOVEDA, blob)


# ───────────────────────────────────────────────────────────────────────────────
# MIGRACIÓN DESDE EL FORMATO ANTIGUO (CSV con metadatos en claro)
# ───────────────────────────────────────────────────────────────────────────────
def _hmac_legacy_valido(clave: str) -> bool | None:
    """True/False si existe el .hmac antiguo; None si no existe."""
    if not ARCHIVO_HMAC_LEGACY.exists():
        return None
    k = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"),
                            b"nebula-hmac-salt-v6", 50_000, 32)
    esperado = hmac.new(k, ARCHIVO_DB_LEGACY.read_bytes(), hashlib.sha256).hexdigest()
    guardado = ARCHIVO_HMAC_LEGACY.read_text(encoding="utf-8").strip()
    return hmac.compare_digest(esperado, guardado)


def migrar_legacy() -> list | None:
    """Lee el CSV antiguo y devuelve la lista de entradas, o None si falla."""
    console.print(Panel(
        "Se importarán las cuentas del formato antiguo a la nueva bóveda cifrada.\n"
        "Introduce la clave maestra con la que las guardaste.\n"
        "[dim]Los archivos antiguos NO se borrarán automáticamente.[/dim]",
        title="Migración", border_style="cyan", expand=False
    ))
    clave_vieja = leer_clave_segura("Clave maestra ANTIGUA")

    try:
        estado = _hmac_legacy_valido(clave_vieja)
        if estado is False:
            _err("Integridad no válida: clave incorrecta o el archivo antiguo fue manipulado.")
            return None
        if estado is None:
            _warn("No hay archivo .hmac antiguo: no se puede verificar la integridad del CSV.")

        with open(ARCHIVO_DB_LEGACY, "r", encoding="utf-8", newline="") as f:
            filas = [r for r in csv.reader(f) if len(r) == 3]
    except OSError as e:
        _err(f"No se pudo leer el archivo antiguo: {e}")
        return None

    entradas, fallidas = [], []
    ahora = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with console.status("[bold]Descifrando entradas antiguas...[/bold]"):
        for sitio, usuario, pwd_hex in filas:
            try:
                pwd = descifrar_nebula(pwd_hex, clave_vieja)
                entradas.append({"sitio": sitio, "usuario": usuario,
                                 "password": pwd, "creado": ahora})
            except (InvalidToken, ValueError, UnicodeDecodeError):
                fallidas.append(sitio)

    if not entradas:
        _err("No se pudo descifrar ninguna entrada con esa clave.")
        return None
    _ok(f"{len(entradas)} entrada(s) importada(s).")
    if fallidas:
        _warn("No se pudieron descifrar (¿otra clave?): "
              + escape(", ".join(fallidas)) + ". Vuelve a añadirlas a mano.")
    return entradas


# ───────────────────────────────────────────────────────────────────────────────
# ARRANQUE DE SESIÓN: la clave maestra se pide UNA sola vez
# ───────────────────────────────────────────────────────────────────────────────
def desbloquear() -> Boveda:
    """
    Reintentos solo por comodidad: NO es una barrera de seguridad (quien tenga
    el archivo puede atacarlo sin este programa). La defensa real es el KDF.
    """
    for intento in range(1, MAX_REINTENTOS_UI + 1):
        clave = leer_clave_segura("Clave maestra")
        try:
            with console.status(f"[bold]Derivando llave ({PBKDF2_ITERACIONES:,} iteraciones) "
                                "y verificando integridad...[/bold]"):
                b = Boveda.abrir(clave)
            del clave
            return b
        except ClaveIncorrectaError as e:
            _err(f"{e}  (intento {intento}/{MAX_REINTENTOS_UI})")
        except BovedaError as e:
            _err(str(e))
            sys.exit(1)
    _err("Demasiados intentos. Cerrando.")
    sys.exit(1)


def crear_boveda_nueva() -> Boveda:
    entradas = None
    if ARCHIVO_DB_LEGACY.exists() and Confirm.ask(
        "\nSe ha detectado una base de datos ANTIGUA (con sitios/usuarios en claro). "
        "¿Migrarla ahora?", default=True
    ):
        entradas = migrar_legacy()
        if entradas is None:
            _err("Migración fallida. No se ha creado ninguna bóveda; vuelve a intentarlo.")
            sys.exit(1)

    console.print("\n[bold yellow]--- CONFIGURAR CLAVE MAESTRA ---[/bold yellow]")
    clave = leer_clave_confirmada("Elige tu clave maestra")
    if clave is None:
        sys.exit(1)

    bits = mostrar_fortaleza(clave)
    if bits < MIN_ENTROPIA_BITS:
        _warn("Clave maestra débil: una frase de paso más larga y variada te protegerá mejor.")
        if not Confirm.ask("¿Continuar de todos modos?", default=False):
            _err("Operación abortada.")
            sys.exit(1)

    with console.status(f"[bold]Ejecutando {PBKDF2_ITERACIONES:,} iteraciones SHA-256...[/bold]"):
        b = Boveda.crear(clave, entradas)
    del clave
    _ok("Bóveda cifrada creada correctamente.")
    _pausa()
    return b


def iniciar_sesion() -> Boveda:
    if ARCHIVO_BOVEDA.exists():
        _cabecera("Desbloquear bóveda")
        return desbloquear()
    _pantalla_bienvenida()
    return crear_boveda_nueva()


# ───────────────────────────────────────────────────────────────────────────────
# SUBMENÚ GESTOR DE CONTRASEÑAS
# ───────────────────────────────────────────────────────────────────────────────
def _pedir_id(entradas: list, texto: str) -> int | None:
    valor = Prompt.ask(f"\n{texto} (ID o 'N' para cancelar)", default="N")
    if valor.strip().upper() == "N":
        return None
    if valor.isdigit() and 1 <= int(valor) <= len(entradas):
        return int(valor) - 1
    _err("ID no válido.")
    return None


def _tabla_entradas(entradas: list) -> None:
    tabla = Table(title="Tus Credenciales Protegidas", header_style="bold magenta")
    tabla.add_column("ID", justify="center", style="cyan")
    tabla.add_column("Sitio / Aplicación", style="white")
    tabla.add_column("Usuario / Correo", style="green")
    tabla.add_column("Contraseña", style="yellow")
    for i, e in enumerate(entradas, 1):
        tabla.add_row(str(i), escape(e["sitio"]), escape(e["usuario"]), "********")
    console.print("\n", tabla)


def _revelar(entrada: dict) -> None:
    modo = "m"
    if pyperclip is not None:
        modo = Prompt.ask(
            f"¿Copiar al portapapeles (se borra en {PORTAPAPELES_SEG}s) o mostrar en pantalla?",
            choices=["c", "m"], default="c"
        )
    if modo == "c":
        if copiar_seguro(entrada["password"]):
            _ok(f"Contraseña de [bold]{escape(entrada['sitio'])}[/bold] copiada. "
                f"Se borrará automáticamente en {PORTAPAPELES_SEG} s.")
            return
        _warn("No hay portapapeles disponible en este entorno; se mostrará en pantalla.")
    console.print(Panel(
        f"[bold green]Sitio:[/bold green] {escape(entrada['sitio'])}\n"
        f"[bold green]Usuario:[/bold green] {escape(entrada['usuario'])}\n"
        f"[bold bright_red]Contraseña:[/bold bright_red] "
        f"[bold white]{escape(entrada['password'])}[/bold white]",
        title="🔓 Credencial Revelada", border_style="red", expand=False
    ))


def submenu_gestor(boveda: Boveda) -> None:
    while True:
        console.clear()
        console.print(LOGO_ASCII, style="bold cyan")
        console.print(Panel("[bold yellow]Gestor Seguro de Contraseñas[/bold yellow]",
                            border_style="yellow", expand=False))
        console.print("[bold green][1][/bold green] Ver mis cuentas guardadas")
        console.print("[bold green][2][/bold green] Registrar nueva contraseña")
        console.print("[bold green][3][/bold green] Eliminar una cuenta")
        console.print("[bold red][4][/bold red] Volver al menú principal\n")

        opt = Prompt.ask("Selecciona una opción", choices=["1", "2", "3", "4"])

        # ── VER ──────────────────────────────────────────────────────────────
        if opt == "1":
            if not boveda.entradas:
                _err("No hay ninguna contraseña guardada todavía.")
                _pausa()
                continue
            _tabla_entradas(boveda.entradas)
            idx = _pedir_id(boveda.entradas, "¿Revelar alguna contraseña?")
            if idx is not None:
                _revelar(boveda.entradas[idx])
            _pausa()

        # ── REGISTRAR ────────────────────────────────────────────────────────
        elif opt == "2":
            console.print("\n[bold yellow]--- REGISTRAR CUENTA ---[/bold yellow]")
            sitio = console.input("[bold white]Aplicación o Web (ej: Netflix, Gmail):[/bold white] ").strip()
            usuario = console.input("[bold white]Usuario o Correo electrónico:[/bold white] ").strip()
            password = leer_clave_segura("Contraseña a guardar (oculta)")

            if not sitio or not usuario or not password:
                _err("Todos los campos son obligatorios.")
            else:
                boveda.entradas.append({
                    "sitio": sitio, "usuario": usuario, "password": password,
                    "creado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                })
                try:
                    with console.status("[bold]Cifrando y guardando bóveda...[/bold]"):
                        boveda.guardar()
                    _ok("Cuenta guardada en la bóveda cifrada.")
                except OSError as e:
                    boveda.entradas.pop()
                    _err(f"No se pudo guardar en disco: {e}")
            _pausa()

        # ── ELIMINAR ─────────────────────────────────────────────────────────
        elif opt == "3":
            if not boveda.entradas:
                _err("No hay cuentas que eliminar.")
                _pausa()
                continue
            _tabla_entradas(boveda.entradas)
            idx = _pedir_id(boveda.entradas, "¿Qué cuenta eliminar?")
            if idx is not None:
                e = boveda.entradas[idx]
                if Confirm.ask(f"¿Eliminar definitivamente '{escape(e['sitio'])}'?", default=False):
                    boveda.entradas.pop(idx)
                    try:
                        boveda.guardar()
                        _ok("Cuenta eliminada.")
                    except OSError as err:
                        boveda.entradas.insert(idx, e)
                        _err(f"No se pudo guardar en disco: {err}")
            _pausa()

        elif opt == "4":
            break


# ───────────────────────────────────────────────────────────────────────────────
# MENÚ PRINCIPAL
# ───────────────────────────────────────────────────────────────────────────────
def nebula_cipher_menu() -> None:
    boveda = iniciar_sesion()   # Clave maestra: UNA sola vez

    while True:
        console.clear()
        console.print(LOGO_ASCII, style="bold cyan")
        console.print(Panel(
            "[bold cyan] NEBULA-NORTHSTAR v6.2 Beta[/bold cyan]\n"
            "[dim]PBKDF2-SHA256 · 600,000 iter · AES-128-CBC+HMAC · Salt 256-bit · "
            "Bóveda cifrada completa[/dim]",
            border_style="bright_magenta", expand=False
        ))
        console.print("[bold green][1][/bold green] Encriptar texto plano")
        console.print("[bold green][2][/bold green] Desencriptar código hexadecimal")
        console.print("[bold green][3][/bold green] Acceder al Gestor de Contraseñas")
        console.print("[bold red][4][/bold red] Salir del programa\n")

        opt = Prompt.ask("Selecciona una opción", choices=["1", "2", "3", "4"])

        # ── ENCRIPTAR TEXTO SUELTO ───────────────────────────────────────────
        if opt == "1":
            console.print("\n[bold yellow]--- ENCRIPTACIÓN ---[/bold yellow]")
            texto = console.input("[bold white]Texto a proteger:[/bold white] ").strip()
            if not texto:
                _err("El texto no puede estar vacío.")
            else:
                clave = leer_clave_confirmada("Clave secreta (oculta, no la olvides)")
                if clave is not None:
                    mostrar_fortaleza(clave)
                    with console.status(f"[bold]Calculando {PBKDF2_ITERACIONES:,} iteraciones...[/bold]"):
                        res = encriptar_nebula(texto, clave)
                    del clave

                    console.print("\n", Panel(
                        "[bold green] El texto ha sido encriptado bajo el protocolo v6.2 Hard beta Secure[/bold green]",
                        title="Proceso Completado!!!", border_style="green", expand=False
                    ))
                    # El hex cifrado no es secreto: se copia sin autoborrado
                    aviso = "[bold green](¡Copiado al portapapeles!)[/bold green]" \
                        if copiar_seguro(res, autoborrar=False) else ""
                    console.print(f"\n  [bold white]📋 CÓDIGO HEXADECIMAL {aviso}:[/bold white]")
                    console.print(f"  [bold yellow]{res}[/bold yellow]\n", soft_wrap=True)
            _pausa()

        # ── DESENCRIPTAR TEXTO SUELTO ────────────────────────────────────────
        elif opt == "2":
            console.print("\n[bold yellow]--- DESENCRIPTACIÓN ---[/bold yellow]")
            texto_hex = console.input("[bold white]Código Hexadecimal:[/bold white] ").strip()
            clave = leer_clave_segura("Clave secreta (oculta)")
            try:
                with console.status("[bold]Derivando llave y descifrando...[/bold]"):
                    res = descifrar_nebula(texto_hex, clave)
                console.print("\n", Panel(
                    f"[bold green]Mensaje Original Recuperado:[/bold green]\n[white]{escape(res)}[/white]",
                    title="Desencriptado", border_style="green", expand=False
                ))
            except ValueError:
                _err("El código introducido no es un formato hexadecimal válido.")
            except (UnicodeDecodeError, InvalidToken):
                _err("Clave incorrecta o datos corruptos/manipulados.")
            del clave
            _pausa()

        elif opt == "3":
            submenu_gestor(boveda)

        elif opt == "4":
            console.print("\n[bold cyan]Cerrando sistema[/bold cyan]\n")
            break


if __name__ == "__main__":
    try:
        nebula_cipher_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Operación cancelada por el usuario.[/bold red]")
        sys.exit(0)