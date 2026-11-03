# ==============================================================================
# Proyecto: TERmita 2.3a
# Autor: APNAPDEV
# Repositorio Oficial: https://github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================

# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027

# NOTA: Termita 2.3a es la primera versión de Termita en la que se hace uso de IA

"""
TERmita - Gestor de Aplicaciones para Windows
=============================================

Herramienta de línea de comandos para listar y desinstalar aplicaciones
instaladas en Windows, leyendo el registro en tres ubicaciones:

    - HKLM, vista de 64 bits  (apps nativas de 64 bits)
    - HKLM, vista de 32 bits  (apps de 32 bits / WOW6432Node)
    - HKCU                    (apps instaladas solo para el usuario actual)

Dependencias:
    pip install rich

Uso:
    python TERmita.py
"""

from __future__ import annotations

import csv
import ctypes
import logging
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable, Optional

try:
    import winreg
except ImportError:  # No estamos en Windows
    winreg = None  # type: ignore

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #

POR_PAGINA = 20  # filas por página en el listado

# Códigos de salida de los desinstaladores (los de Windows Installer incluidos)
CODIGOS_SIN_ERROR = {0, 3010, 1641}   # éxito / éxito + reinicio necesario
CODIGOS_REINICIO = {3010, 1641}
MENSAJES_CODIGO = {
    1223: "operación cancelada por el usuario",
    1602: "desinstalación cancelada por el usuario",
    1603: "error fatal durante la desinstalación",
    1605: "Windows Installer no encuentra el producto instalado",
    1618: "hay otra instalación o desinstalación en curso",
}

# Tras ejecutar el desinstalador, cuántas veces y con qué pausa se comprueba
# si la clave del registro ya ha desaparecido (algunos desinstaladores
# lanzan otro proceso y terminan antes de acabar el trabajo).
VERIFICACION_INTENTOS = 6
VERIFICACION_PAUSA = 0.5  # segundos


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def _directorio_base() -> Path:
    """Carpeta donde vive el programa.

    Si está empaquetado con PyInstaller (--onefile), sys.executable apunta
    al .exe real; __file__ apuntaría a la carpeta temporal _MEIPASS, que se
    borra al cerrar el programa, así que ahí no debe escribirse el log.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _directorio_logs() -> Optional[Path]:
    """Primera carpeta donde se pueda escribir el log, o None si no hay ninguna.

    Se prueba junto al programa y, si está en una ubicación de solo lectura
    (p. ej. Program Files), en %LOCALAPPDATA% y por último en la carpeta temporal.
    """
    candidatos = [_directorio_base() / "logs"]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidatos.append(Path(local) / "TERmita" / "logs")
    candidatos.append(Path(tempfile.gettempdir()) / "TERmita" / "logs")

    for carpeta in candidatos:
        try:
            carpeta.mkdir(parents=True, exist_ok=True)
            prueba = carpeta / ".escritura_ok"
            prueba.touch()
            prueba.unlink()
            return carpeta
        except OSError:
            continue
    return None


LOG_DIR = _directorio_logs()
LOG_FILE = LOG_DIR / "gestor_aplicaciones.log" if LOG_DIR else None


def configurar_logging() -> logging.Logger:
    """Configura un logger con rotación de archivo para trazabilidad.

    Si no hay ninguna carpeta escribible, el programa sigue funcionando
    sin log en lugar de fallar al arrancar.
    """
    logger = logging.getLogger("gestor_aplicaciones")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:  # Evita duplicar handlers si el módulo se recarga
        handler: logging.Handler
        try:
            if LOG_FILE is None:
                raise OSError("sin carpeta de logs escribible")
            handler = RotatingFileHandler(
                LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(funcName)s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
        except OSError:
            handler = logging.NullHandler()
        logger.addHandler(handler)

    return logger


logger = configurar_logging()
console = Console()


# --------------------------------------------------------------------------- #
# Utilidades puras (sin registro ni consola: fáciles de probar)
# --------------------------------------------------------------------------- #

def _normalizar(texto: str) -> str:
    """Minúsculas y sin acentos, para búsquedas tolerantes ('camara' == 'Cámara')."""
    descompuesto = unicodedata.normalize("NFD", texto.lower())
    return "".join(c for c in descompuesto if unicodedata.category(c) != "Mn")


def formatear_tamanio(kb: Optional[int]) -> str:
    """Tamaño legible a partir de KB ('-' si se desconoce)."""
    if not kb:
        return "-"
    if kb < 1024:
        return f"{kb} KB"
    mb = kb / 1024
    if mb < 1024:
        return f"{mb:.1f} MB"
    return f"{mb / 1024:.2f} GB"


# Muchos instaladores MSI registran "msiexec /I{GUID}" (modificar/reparar)
# en vez de "/X{GUID}" (desinstalar). Se corrige para que realmente desinstale.
_PATRON_MSI_INSTALAR = re.compile(r"(?i)(msiexec(?:\.exe)?[\"']?\s+)/I(?=[\s{])")


def normalizar_comando_msi(comando: str) -> str:
    """Cambia 'msiexec /I' por 'msiexec /X' para que el comando desinstale."""
    return _PATRON_MSI_INSTALAR.sub(r"\1/X", comando)


def parsear_seleccion(texto: str, maximo: int) -> list[int]:
    """Convierte '3,5,8-12' en [3, 5, 8, 9, 10, 11, 12] (ordenado y sin repetidos).

    Lanza ValueError con un mensaje legible si algo no es válido o está fuera de 1..maximo.
    """
    texto = re.sub(r"\s*-\s*", "-", texto.strip())
    elegidos: set[int] = set()

    for trozo in re.split(r"[,;\s]+", texto):
        if not trozo:
            continue
        rango = re.fullmatch(r"(\d+)-(\d+)", trozo)
        if rango:
            inicio, fin = int(rango.group(1)), int(rango.group(2))
            if inicio > fin:
                raise ValueError(f"El rango «{trozo}» está al revés (debería ser {fin}-{inicio}).")
            extremos = (inicio, fin)
        elif trozo.isdigit():
            extremos = (int(trozo), int(trozo))
        else:
            raise ValueError(f"«{trozo}» no es un número ni un rango válido.")

        for n in extremos:
            if not 1 <= n <= maximo:
                raise ValueError(f"El número {n} está fuera de rango (1-{maximo}).")
        elegidos.update(range(extremos[0], extremos[1] + 1))

    return sorted(elegidos)


def paginar(total: int, pagina: int, por_pagina: int = POR_PAGINA) -> tuple[int, int, int, int]:
    """Devuelve (pagina_ajustada, total_paginas, indice_inicio, indice_fin) sobre una lista."""
    total_paginas = max(1, math.ceil(total / por_pagina))
    pagina = min(max(pagina, 1), total_paginas)
    inicio = (pagina - 1) * por_pagina
    fin = min(inicio + por_pagina, total)
    return pagina, total_paginas, inicio, fin


def _celda_segura(valor: str) -> str:
    """Evita que Excel interprete como fórmula un texto que empiece por = + - @."""
    if valor and valor[0] in "=+-@\t\r":
        return "'" + valor
    return valor


# --------------------------------------------------------------------------- #
# Modelo de datos
# --------------------------------------------------------------------------- #

@dataclass
class Aplicacion:
    """Representa una aplicación instalada, tal como aparece en el registro."""

    nombre: str
    origen: str  # "HKLM64", "HKLM32" o "HKCU"
    version: Optional[str] = None
    publisher: Optional[str] = None
    fecha_instalacion: Optional[str] = None
    tamanio_kb: Optional[int] = None
    uninstall_string: Optional[str] = None
    quiet_uninstall_string: Optional[str] = None
    es_componente_sistema: bool = False
    ruta_instalacion: Optional[str] = None
    unidad: str = "Desconocida"  # "C:", "D:", "Red" o "Desconocida"

    # Dónde vive su clave en el registro (permite comprobar si se desinstaló)
    hive: Optional[int] = field(default=None, repr=False)
    flags_wow64: int = field(default=0, repr=False)
    subclave: Optional[str] = field(default=None, repr=False)

    @property
    def fecha_orden(self) -> Optional[str]:
        """'YYYYMMDD' si la fecha del registro tiene ese formato; si no, None."""
        f = self.fecha_instalacion
        return f if f and len(f) == 8 and f.isdigit() else None

    @property
    def fecha_legible(self) -> str:
        f = self.fecha_orden
        if f:
            return f"{f[:4]}-{f[4:6]}-{f[6:]}"
        return self.fecha_instalacion or "-"

    def elegir_comando(self, silencioso: bool = False) -> tuple[Optional[str], bool]:
        """Devuelve (comando, es_silencioso) para desinstalar, o (None, False) si no hay.

        Solo se usa la desinstalación silenciosa si se pide expresamente (o si
        es la única disponible). El comando normal se corrige si es un
        'msiexec /I' (que repararía en vez de desinstalar).
        """
        if silencioso and self.quiet_uninstall_string:
            return self.quiet_uninstall_string.strip(), True
        if self.uninstall_string:
            comando = self.uninstall_string.strip()
            corregido = normalizar_comando_msi(comando)
            if corregido != comando:
                logger.info("Comando de '%s' corregido de /I a /X: %s", self.nombre, corregido)
            return corregido, False
        if self.quiet_uninstall_string:
            return self.quiet_uninstall_string.strip(), True
        return None, False


@dataclass
class ResultadoDesinstalacion:
    """Resultado de intentar desinstalar una aplicación.

    estado:
        "ok"           la clave del registro desapareció
        "ok_reinicio"  desapareció, pero hay que reiniciar Windows
        "incierta"     el desinstalador terminó sin error pero la clave sigue ahí
        "fallida"      el desinstalador devolvió un código de error
        "error"        no se pudo ni ejecutar el comando
        "sin_comando"  la app no tiene comando de desinstalación registrado
    """

    nombre: str
    estado: str
    codigo: Optional[int] = None
    detalle: str = ""

    @property
    def fallo(self) -> bool:
        return self.estado in ("fallida", "error", "sin_comando")


def ordenar_aplicaciones(
    apps: list[Aplicacion], criterio: str = "nombre", descendente: bool = False
) -> list[Aplicacion]:
    """Ordena por 'nombre', 'tamano' o 'fecha'. Las que no tienen dato van siempre al final."""
    if criterio == "nombre":
        return sorted(apps, key=lambda a: _normalizar(a.nombre), reverse=descendente)

    clave: Callable[[Aplicacion], object]
    if criterio == "tamano":
        clave = lambda a: a.tamanio_kb  # noqa: E731
    elif criterio == "fecha":
        clave = lambda a: a.fecha_orden  # noqa: E731
    else:
        raise ValueError(f"Criterio de orden desconocido: {criterio}")

    con_dato = [a for a in apps if clave(a) is not None]
    sin_dato = [a for a in apps if clave(a) is None]
    con_dato.sort(key=clave, reverse=descendente)  # type: ignore[arg-type]
    sin_dato.sort(key=lambda a: _normalizar(a.nombre))
    return con_dato + sin_dato


# --------------------------------------------------------------------------- #
# Acceso al registro / lógica de negocio
# --------------------------------------------------------------------------- #

class GestorAplicacionesWindows:
    """Consulta y desinstala aplicaciones instaladas, usando el registro de Windows."""

    RUTA_DESINSTALACION = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    def __init__(self, incluir_componentes_sistema: bool = False):
        if winreg is None:
            raise RuntimeError(
                "GestorAplicacionesWindows solo funciona en Windows "
                "(el módulo 'winreg' no está disponible)."
            )
        self.incluir_componentes_sistema = incluir_componentes_sistema
        self._cache: list[Aplicacion] = []

    # -- Ubicaciones a inspeccionar ---------------------------------------- #

    @staticmethod
    def _ubicaciones() -> list[tuple[int, int, str]]:
        """(hive, flags_wow64, etiqueta) para cada ubicación del registro a escanear."""
        return [
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "HKLM64"),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "HKLM32"),
            (winreg.HKEY_CURRENT_USER, 0, "HKCU"),
        ]

    # Letra de unidad (no precedida por otra letra, para no confundir "https://")
    _PATRON_UNIDAD = re.compile(r"(?<![A-Za-z])([A-Za-z]):[\\/]")

    # Rutas que NO indican dónde está instalada la app: la caché de Windows
    # Installer, los ejecutables del sistema (msiexec.exe...) y la caché de
    # paquetes. Un MSI instalado en D: suele apuntar su icono a C:\Windows\Installer.
    _PATRON_RUTA_NO_FIABLE = re.compile(
        r"^[A-Za-z]:\\(?:windows\\|programdata\\package cache\\)", re.IGNORECASE
    )

    @classmethod
    def _detectar_unidad(cls, *candidatos: Optional[str]) -> str:
        """Deduce el disco de una app a partir de las rutas disponibles, en orden de fiabilidad."""
        for texto in candidatos:
            if not texto or not isinstance(texto, str):
                continue
            texto = os.path.expandvars(texto.strip().strip('"'))
            if texto.startswith("\\\\"):
                return "Red"
            for coincidencia in cls._PATRON_UNIDAD.finditer(texto):
                desde_aqui = texto[coincidencia.start():].replace("/", "\\")
                if cls._PATRON_RUTA_NO_FIABLE.match(desde_aqui):
                    continue  # esta ruta no dice dónde está la app; probar la siguiente
                return f"{coincidencia.group(1).upper()}:"
        return "Desconocida"

    @staticmethod
    def _leer_valor(clave, nombre: str, por_defecto=None):
        try:
            return winreg.QueryValueEx(clave, nombre)[0]
        except OSError:
            return por_defecto

    @staticmethod
    def _a_entero(valor) -> Optional[int]:
        """Entero positivo o None (EstimatedSize a 0 significa 'desconocido')."""
        try:
            n = int(valor)
        except (TypeError, ValueError):
            return None
        return n if n > 0 else None

    @staticmethod
    def _a_texto(valor) -> Optional[str]:
        if valor is None:
            return None
        texto = str(valor).strip()
        return texto or None

    def _leer_aplicacion(
        self, hive: int, flags: int, etiqueta: str, subclave_nombre: str
    ) -> Optional[Aplicacion]:
        """Lee los valores de una subclave y construye un Aplicacion, o None si no aplica."""
        ruta_completa = f"{self.RUTA_DESINSTALACION}\\{subclave_nombre}"
        try:
            with winreg.OpenKey(hive, ruta_completa, 0, winreg.KEY_READ | flags) as clave_app:
                nombre = self._a_texto(self._leer_valor(clave_app, "DisplayName"))
                if not nombre:
                    return None  # Sin nombre visible: no es una app "real"

                es_componente = self._a_entero(self._leer_valor(clave_app, "SystemComponent", 0)) is not None
                if es_componente and not self.incluir_componentes_sistema:
                    return None

                ruta_instalacion = self._a_texto(self._leer_valor(clave_app, "InstallLocation"))
                display_icon = self._leer_valor(clave_app, "DisplayIcon")
                uninstall_string = self._a_texto(self._leer_valor(clave_app, "UninstallString"))
                quiet_uninstall_string = self._a_texto(self._leer_valor(clave_app, "QuietUninstallString"))

                # Orden de fiabilidad: carpeta de instalación > icono (apunta al .exe) > desinstalador
                unidad = self._detectar_unidad(
                    ruta_instalacion, display_icon, uninstall_string, quiet_uninstall_string
                )

                return Aplicacion(
                    nombre=nombre,
                    origen=etiqueta,
                    version=self._a_texto(self._leer_valor(clave_app, "DisplayVersion")),
                    publisher=self._a_texto(self._leer_valor(clave_app, "Publisher")),
                    fecha_instalacion=self._a_texto(self._leer_valor(clave_app, "InstallDate")),
                    tamanio_kb=self._a_entero(self._leer_valor(clave_app, "EstimatedSize")),
                    uninstall_string=uninstall_string,
                    quiet_uninstall_string=quiet_uninstall_string,
                    es_componente_sistema=es_componente,
                    ruta_instalacion=ruta_instalacion,
                    unidad=unidad,
                    hive=hive,
                    flags_wow64=flags,
                    subclave=subclave_nombre,
                )
        except OSError as exc:
            logger.debug("No se pudo leer %s (%s): %s", subclave_nombre, etiqueta, exc)
            return None

    # -- API pública --------------------------------------------------------- #

    def listar_aplicaciones(self, forzar_actualizacion: bool = False) -> list[Aplicacion]:
        """Escanea el registro (con caché) y devuelve la lista de aplicaciones instaladas."""
        if self._cache and not forzar_actualizacion:
            return self._cache

        aplicaciones: list[Aplicacion] = []
        vistos = set()

        for hive, flags, etiqueta in self._ubicaciones():
            try:
                clave_raiz = winreg.OpenKey(
                    hive, self.RUTA_DESINSTALACION, 0, winreg.KEY_READ | flags
                )
            except OSError as exc:
                logger.warning("No se pudo abrir el registro para %s: %s", etiqueta, exc)
                continue

            try:
                total = winreg.QueryInfoKey(clave_raiz)[0]
                for i in range(total):
                    try:
                        subclave_nombre = winreg.EnumKey(clave_raiz, i)
                    except OSError:
                        continue

                    app = self._leer_aplicacion(hive, flags, etiqueta, subclave_nombre)
                    if app is None:
                        continue

                    # Misma app solo si coinciden nombre, versión, origen y carpeta:
                    # dos versiones (o dos instalaciones) distintas no se descartan.
                    identificador = (app.nombre.lower(), app.version, app.origen, app.ruta_instalacion)
                    if identificador in vistos:
                        continue
                    vistos.add(identificador)
                    aplicaciones.append(app)
            finally:
                winreg.CloseKey(clave_raiz)

        aplicaciones.sort(key=lambda a: _normalizar(a.nombre))
        self._cache = aplicaciones
        logger.info("Escaneo completado: %d aplicaciones encontradas.", len(aplicaciones))
        return aplicaciones

    def unidades_disponibles(self) -> list[str]:
        """Unidades en las que hay al menos una aplicación detectada (ej. ['C:', 'D:'])."""
        return sorted({a.unidad for a in self.listar_aplicaciones()})

    def buscar_aplicaciones(
        self, consulta: str = "", unidad: Optional[str] = None
    ) -> list[Aplicacion]:
        """Filtra por texto (en nombre o editor, sin acentos ni mayúsculas) y/o por unidad.

        Cada palabra de la consulta debe aparecer en el nombre o el editor.
        Con consulta vacía y unidad=None devuelve todas las aplicaciones.
        """
        palabras = _normalizar(consulta).split()
        resultado = []
        for a in self.listar_aplicaciones():
            if unidad is not None and a.unidad != unidad:
                continue
            pajar = _normalizar(f"{a.nombre} {a.publisher or ''}")
            if all(p in pajar for p in palabras):
                resultado.append(a)
        return resultado

    def _sigue_instalada(self, app: Aplicacion) -> bool:
        """True si la clave de la app sigue en el registro (o no se puede comprobar)."""
        if app.hive is None or not app.subclave:
            return True  # sin datos para comprobarlo, no afirmamos que haya desaparecido
        ruta = f"{self.RUTA_DESINSTALACION}\\{app.subclave}"
        try:
            with winreg.OpenKey(app.hive, ruta, 0, winreg.KEY_READ | app.flags_wow64):
                return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            logger.debug("No se pudo comprobar la clave de '%s': %s", app.nombre, exc)
            return True

    def desinstalar(self, app: Aplicacion, silencioso: bool = False) -> ResultadoDesinstalacion:
        """Ejecuta el desinstalador y comprueba en el registro si realmente desapareció.

        No imprime nada: devuelve un ResultadoDesinstalacion para que lo muestre la interfaz.
        """
        comando, es_silencioso = app.elegir_comando(silencioso)
        if not comando:
            logger.error("'%s' no tiene comando de desinstalación registrado.", app.nombre)
            return ResultadoDesinstalacion(app.nombre, "sin_comando")

        logger.info(
            "Iniciando desinstalación de '%s' (%s, %s): %s",
            app.nombre, app.origen, "silenciosa" if es_silencioso else "con ventana", comando,
        )

        try:
            proceso = subprocess.run(comando, shell=True)
        except Exception as exc:
            logger.exception("Error al ejecutar el desinstalador de '%s'", app.nombre)
            return ResultadoDesinstalacion(app.nombre, "error", detalle=str(exc))

        codigo = proceso.returncode
        sigue = self._sigue_instalada(app)
        if sigue and codigo in CODIGOS_SIN_ERROR:
            # Puede que el desinstalador siga trabajando en otro proceso: esperar un poco.
            for _ in range(VERIFICACION_INTENTOS):
                time.sleep(VERIFICACION_PAUSA)
                sigue = self._sigue_instalada(app)
                if not sigue:
                    break

        reinicio = codigo in CODIGOS_REINICIO
        if not sigue:
            estado = "ok_reinicio" if reinicio else "ok"
        elif codigo in CODIGOS_SIN_ERROR:
            estado = "incierta"
        else:
            estado = "fallida"

        logger.info("Desinstalación de '%s': estado=%s, código=%d.", app.nombre, estado, codigo)
        self._cache = []  # invalidar caché para reflejar el cambio
        return ResultadoDesinstalacion(
            app.nombre, estado, codigo, MENSAJES_CODIGO.get(codigo, "")
        )

    def exportar_csv(self, ruta: Path, apps: Optional[list[Aplicacion]] = None) -> int:
        """Exporta aplicaciones a CSV (por defecto todas; o la lista que se indique).

        Devuelve cuántas se exportaron.
        """
        if apps is None:
            apps = self.listar_aplicaciones()
        with ruta.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Nombre", "Versión", "Editor", "Origen", "Unidad", "Ubicación", "Fecha instalación", "Tamaño (KB)"])
            for a in apps:
                writer.writerow(
                    [_celda_segura(a.nombre), _celda_segura(a.version or ""),
                     _celda_segura(a.publisher or ""), a.origen, a.unidad,
                     _celda_segura(a.ruta_instalacion or ""),
                     a.fecha_instalacion or "", a.tamanio_kb or ""]
                )
        logger.info("Lista exportada a %s (%d aplicaciones).", ruta, len(apps))
        return len(apps)


# --------------------------------------------------------------------------- #
# Utilidades de sistema
# --------------------------------------------------------------------------- #

def es_admin() -> bool:
    """Comprueba si el proceso actual se ejecuta con privilegios de administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1  # type: ignore[attr-defined]
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Interfaz de línea de comandos (Rich)
# --------------------------------------------------------------------------- #

# r"""...""": cadena cruda, las barras invertidas se conservan tal cual.
LOGO = r"""
████████╗███████╗██████╗ ███╗   ███╗██╗████████╗ █████╗ 
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║╚══██╔══╝██╔══██╗
   ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║   ███████║
   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║   ██╔══██║
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║   ██║   ██║  ██║
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
""".strip("\n")

SUBTITULO = "Gestor de Aplicaciones — Windows"
DESCRIPCION = "Consulta y desinstala programas instalados desde el registro."

# Opciones del menú de ordenación: clave -> (texto, criterio, descendente)
ORDENES = {
    "1": ("Nombre (A → Z)", "nombre", False),
    "2": ("Nombre (Z → A)", "nombre", True),
    "3": ("Tamaño (mayor primero)", "tamano", True),
    "4": ("Tamaño (menor primero)", "tamano", False),
    "5": ("Fecha de instalación (más reciente primero)", "fecha", True),
    "6": ("Fecha de instalación (más antigua primero)", "fecha", False),
}


def _degradado(n, inicio=(0, 229, 255), fin=(41, 98, 255)):
    """n colores 'rgb(r,g,b)' interpolados de inicio a fin (Rich los adapta al terminal)."""
    pasos = max(n - 1, 1)
    return [
        "rgb({},{},{})".format(*(round(a + (b - a) * i / pasos) for a, b in zip(inicio, fin)))
        for i in range(n)
    ]


def mostrar_banner() -> None:
    lineas = LOGO.splitlines()
    ancho_logo = max(len(linea) for linea in lineas)
    ancho = max(ancho_logo, len(DESCRIPCION))
    sangria = " " * ((ancho - ancho_logo) // 2)  # centra el dibujo como bloque, sin deformarlo

    texto = Text()
    for linea, color in zip(lineas, _degradado(len(lineas))):
        texto.append(f"{sangria}{linea}\n", style=f"bold {color}")
    texto.append("\n")
    texto.append(f"{SUBTITULO.center(ancho)}\n", style="bold white")
    texto.append(DESCRIPCION.center(ancho), style="dim")

    console.print(Panel.fit(texto, border_style="cyan", padding=(1, 3)))


@dataclass
class EstadoVista:
    """Qué se está viendo: filtros, orden y página actual."""

    consulta: str = ""
    unidad: Optional[str] = None
    criterio: str = "nombre"
    descendente: bool = False
    pagina: int = 1

    @property
    def descripcion_orden(self) -> str:
        for texto, criterio, descendente in ORDENES.values():
            if (criterio, descendente) == (self.criterio, self.descendente):
                return texto
        return self.criterio

    @property
    def hay_filtros(self) -> bool:
        return bool(self.consulta or self.unidad)

    @property
    def descripcion_filtros(self) -> str:
        partes = []
        if self.consulta:
            partes.append(f"texto «{self.consulta}»")
        if self.unidad:
            partes.append(f"unidad {self.unidad}")
        return ", ".join(partes) if partes else "ninguno"


def mostrar_tabla(apps: list[Aplicacion], estado: EstadoVista, por_pagina: int = POR_PAGINA) -> int:
    """Muestra una página del listado y devuelve el número de página realmente mostrado.

    La columna # es la posición en la lista completa (no en la página), así que
    los números siguen valiendo para desinstalar aunque cambies de página.
    """
    pagina, total_paginas, inicio, fin = paginar(len(apps), estado.pagina, por_pagina)

    caption = (
        f"Página {pagina}/{total_paginas} · {len(apps)} aplicaciones · "
        f"Orden: {escape(estado.descripcion_orden)} · "
        f"Filtros: {escape(estado.descripcion_filtros)}"
    )
    tabla = Table(
        title="Aplicaciones instaladas", caption=caption, caption_justify="left",
        box=box.ROUNDED, header_style="bold cyan",
    )
    tabla.add_column("#", justify="right", style="dim")
    tabla.add_column("Nombre", style="bold", overflow="ellipsis", no_wrap=True, max_width=42)
    tabla.add_column("Versión", overflow="ellipsis", no_wrap=True, max_width=18)
    tabla.add_column("Editor", overflow="ellipsis", no_wrap=True, max_width=24)
    tabla.add_column("Tamaño", justify="right")
    tabla.add_column("Instalada", justify="center")
    tabla.add_column("Origen", justify="center")
    tabla.add_column("Unidad", justify="center")

    for i, app in enumerate(apps[inicio:fin], start=inicio + 1):
        tabla.add_row(
            str(i), escape(app.nombre), escape(app.version or "-"), escape(app.publisher or "-"),
            formatear_tamanio(app.tamanio_kb), app.fecha_legible, app.origen, app.unidad,
        )

    console.print(tabla)
    return pagina


def mostrar_plan(plan: list[tuple[Aplicacion, Optional[str], bool]]) -> None:
    """Enseña qué comando exacto se va a ejecutar para cada aplicación, ANTES de confirmar."""
    tabla = Table(title="Se va a ejecutar", box=box.ROUNDED, header_style="bold cyan")
    tabla.add_column("Aplicación", style="bold", overflow="fold")
    tabla.add_column("Modo", justify="center", no_wrap=True)
    tabla.add_column("Comando", overflow="fold")

    for app, comando, silencioso in plan:
        if not comando:
            tabla.add_row(escape(app.nombre), "[red]—[/red]", "[red]Sin comando de desinstalación registrado[/red]")
        else:
            modo = "[yellow]silencioso[/yellow]" if silencioso else "con ventana"
            tabla.add_row(escape(app.nombre), modo, escape(comando))
    console.print(tabla)

    if any(app.origen == "HKCU" for app, _, _ in plan):
        console.print(
            "[dim]Las entradas HKCU las puede modificar cualquier programa de tu usuario: "
            "comprueba que el comando es el que esperas.[/dim]"
        )
    if any(silencioso for _, _, silencioso in plan):
        console.print("[dim]Modo silencioso: no verás ventanas ni podrás cancelar el proceso.[/dim]")


def mostrar_resultado(res: ResultadoDesinstalacion) -> None:
    nombre = escape(res.nombre)
    detalle = f" ({escape(res.detalle)})" if res.detalle else ""

    if res.estado == "ok":
        console.print(f"[green]«{nombre}» se desinstaló correctamente.[/green]")
    elif res.estado == "ok_reinicio":
        console.print(
            f"[green]«{nombre}» se desinstaló.[/green] "
            "[yellow]Hay que reiniciar Windows para completar el proceso.[/yellow]"
        )
    elif res.estado == "incierta":
        console.print(
            f"[yellow]El desinstalador de «{nombre}» terminó sin errores, pero la aplicación "
            "sigue en el registro. Puede estar acabando en segundo plano: "
            "vuelve a listar en unos instantes.[/yellow]"
        )
    elif res.estado == "fallida":
        console.print(
            f"[yellow]El desinstalador de «{nombre}» terminó con código {res.codigo}{detalle}. "
            "Puede que se haya cancelado o requiera revisión manual.[/yellow]"
        )
    elif res.estado == "error":
        console.print(f"[red]No se pudo ejecutar el desinstalador de «{nombre}»: {escape(res.detalle)}[/red]")
    else:  # sin_comando
        console.print(f"[red]No se encontró un comando de desinstalación para «{nombre}».[/red]")


def mostrar_resumen(resultados: list[ResultadoDesinstalacion]) -> None:
    etiquetas = {
        "ok": "[green]Desinstalada[/green]",
        "ok_reinicio": "[green]Desinstalada[/green] (reinicio necesario)",
        "incierta": "[yellow]Sin confirmar[/yellow]",
        "fallida": "[yellow]Fallida[/yellow]",
        "error": "[red]Error[/red]",
        "sin_comando": "[red]Sin comando[/red]",
    }
    tabla = Table(title="Resumen", box=box.ROUNDED, header_style="bold cyan")
    tabla.add_column("Aplicación", style="bold", overflow="fold")
    tabla.add_column("Resultado")
    for res in resultados:
        tabla.add_row(escape(res.nombre), etiquetas.get(res.estado, res.estado))
    console.print(tabla)


class Interfaz:
    """Menú interactivo: guarda el estado de la vista (filtros, orden, página)."""

    def __init__(self, gestor: GestorAplicacionesWindows):
        self.gestor = gestor
        self.estado = EstadoVista()
        # True si la tabla en pantalla corresponde a la vista actual, es decir,
        # los números de la columna # son los que el usuario puede teclear.
        self._numeracion_visible = False

    # -- Vista --------------------------------------------------------------- #

    def _apps_vista(self) -> list[Aplicacion]:
        """Aplicaciones de la vista actual: filtradas y ordenadas."""
        with console.status("Leyendo el registro..."):
            apps = self.gestor.buscar_aplicaciones(self.estado.consulta, self.estado.unidad)
        return ordenar_aplicaciones(apps, self.estado.criterio, self.estado.descendente)

    def mostrar(self) -> list[Aplicacion]:
        apps = self._apps_vista()
        if not apps:
            console.print("[yellow]No hay aplicaciones que coincidan con los filtros actuales.[/yellow]")
            self._numeracion_visible = False
            return apps
        self.estado.pagina = mostrar_tabla(apps, self.estado)
        self._numeracion_visible = True
        return apps

    # -- Acciones del menú --------------------------------------------------- #

    def accion_ver(self) -> None:
        self.estado.pagina = 1
        self.mostrar()

    def accion_pagina(self, delta: int) -> None:
        apps = self._apps_vista()
        _, total_paginas, _, _ = paginar(len(apps), self.estado.pagina)
        nueva = self.estado.pagina + delta
        if nueva < 1:
            console.print("[yellow]Ya estás en la primera página.[/yellow]")
        elif nueva > total_paginas:
            console.print("[yellow]Ya estás en la última página.[/yellow]")
        else:
            self.estado.pagina = nueva
            self.mostrar()

    def accion_buscar(self) -> None:
        consulta = Prompt.ask(
            "Nombre o editor a buscar (vacío = quitar la búsqueda)", default="", show_default=False
        )
        self.estado.consulta = consulta.strip()
        self.estado.pagina = 1
        self.mostrar()

    def accion_unidad(self) -> None:
        with console.status("Leyendo el registro..."):
            unidades = self.gestor.unidades_disponibles()
        if not unidades:
            console.print("[yellow]No hay aplicaciones detectadas.[/yellow]")
            return
        unidad = Prompt.ask(
            "Unidad a mostrar", choices=unidades + ["Todas"],
            default=self.estado.unidad or "Todas", case_sensitive=False,
        )
        self.estado.unidad = None if unidad.lower() == "todas" else unidad
        self.estado.pagina = 1
        self.mostrar()

    def accion_orden(self) -> None:
        console.print("\n[bold]Ordenar por[/bold]")
        for clave, (texto, _, _) in ORDENES.items():
            console.print(f"  [cyan]{clave}[/cyan]. {texto}")
        eleccion = Prompt.ask("Elige un orden", choices=list(ORDENES), default="1")
        _, self.estado.criterio, self.estado.descendente = ORDENES[eleccion]
        self.estado.pagina = 1
        self.mostrar()

    def accion_quitar_filtros(self) -> None:
        self.estado.consulta = ""
        self.estado.unidad = None
        self.estado.pagina = 1
        self.mostrar()

    def accion_componentes_sistema(self) -> None:
        self.gestor.incluir_componentes_sistema = not self.gestor.incluir_componentes_sistema
        with console.status("Actualizando lista..."):
            self.gestor.listar_aplicaciones(forzar_actualizacion=True)
        estado = "incluidos" if self.gestor.incluir_componentes_sistema else "ocultos"
        console.print(f"[cyan]Componentes del sistema {estado}.[/cyan]")
        self.estado.pagina = 1
        self.mostrar()

    def accion_exportar(self) -> None:
        apps = self._apps_vista()
        if not apps:
            console.print("[yellow]No hay nada que exportar con los filtros actuales.[/yellow]")
            return
        if self.estado.hay_filtros:
            console.print(
                f"[dim]Se exportará la vista filtrada ({len(apps)} aplicaciones). "
                "Quita los filtros para exportarlas todas.[/dim]"
            )
        ruta = Path(Prompt.ask("Ruta del archivo CSV", default="aplicaciones_instaladas.csv"))
        try:
            total = self.gestor.exportar_csv(ruta, apps)
            console.print(f"[green]{total} aplicaciones exportadas a {escape(str(ruta.resolve()))}[/green]")
        except OSError as exc:
            logger.exception("Error exportando a CSV")
            console.print(f"[red]No se pudo exportar: {escape(str(exc))}[/red]")

    def accion_desinstalar(self) -> None:
        apps = self._apps_vista()
        if not apps:
            console.print("[yellow]No hay aplicaciones que desinstalar con los filtros actuales.[/yellow]")
            return
        if not self._numeracion_visible:
            self.estado.pagina = mostrar_tabla(apps, self.estado)
            self._numeracion_visible = True

        console.print("[dim]Los números son los de la columna #, de cualquier página.[/dim]")
        texto = Prompt.ask(
            "Números a desinstalar (ej. 3,5,8-12; vacío = cancelar)", default="", show_default=False
        )
        if not texto.strip():
            return
        try:
            indices = parsear_seleccion(texto, len(apps))
        except ValueError as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            return
        seleccion = [apps[i - 1] for i in indices]

        silencioso = False
        if any(a.quiet_uninstall_string for a in seleccion):
            silencioso = Confirm.ask(
                "Algunas aplicaciones ofrecen desinstalación silenciosa. "
                "¿Usarla? (sin ventanas: no podrás ver mensajes ni cancelar)",
                default=False,
            )

        plan = [(a, *a.elegir_comando(silencioso)) for a in seleccion]
        mostrar_plan(plan)

        ejecutables = sum(1 for _, comando, _ in plan if comando)
        if ejecutables == 0:
            console.print("[red]Ninguna de las aplicaciones elegidas se puede desinstalar desde aquí.[/red]")
            return
        if not Confirm.ask(f"¿Confirmas que quieres desinstalar {ejecutables} aplicación(es)?", default=False):
            return

        resultados: list[ResultadoDesinstalacion] = []
        for posicion, (app, comando, _) in enumerate(plan):
            if comando:
                console.print(Panel(
                    f"[cyan]Ejecutando:[/cyan] {escape(comando)}",
                    title=f"Desinstalando {escape(app.nombre)}",
                ))
            res = self.gestor.desinstalar(app, silencioso)
            resultados.append(res)
            mostrar_resultado(res)

            quedan = len(plan) - posicion - 1
            if res.fallo and quedan and not Confirm.ask(
                f"¿Continuar con las {quedan} restantes?", default=True
            ):
                break

        if len(resultados) > 1:
            mostrar_resumen(resultados)
        if any(r.estado == "ok_reinicio" for r in resultados):
            console.print("[yellow]Algunas desinstalaciones requieren reiniciar Windows.[/yellow]")

        self._numeracion_visible = False  # la lista ha cambiado: hay que volver a mostrarla

    # -- Bucle principal ----------------------------------------------------- #

    def _opciones(self) -> dict[str, tuple[str, Optional[Callable[[], None]]]]:
        incluir = self.gestor.incluir_componentes_sistema
        return {
            "1": ("Ver aplicaciones", self.accion_ver),
            "2": ("Buscar por nombre o editor", self.accion_buscar),
            "3": ("Filtrar por unidad (disco)", self.accion_unidad),
            "4": ("Cambiar el orden (nombre, tamaño, fecha)", self.accion_orden),
            "5": ("Desinstalar una o varias aplicaciones", self.accion_desinstalar),
            "6": ("Exportar la lista a CSV", self.accion_exportar),
            "7": (("Ocultar" if incluir else "Mostrar") + " componentes del sistema",
                  self.accion_componentes_sistema),
            "8": ("Quitar filtros", self.accion_quitar_filtros),
            "0": ("Salir", None),
        }

    def ejecutar(self) -> None:
        mostrar_banner()

        if not es_admin():
            console.print(
                "[yellow]⚠ No se está ejecutando como administrador. "
                "Algunas desinstalaciones podrían fallar o pedir permisos elevados.[/yellow]\n"
            )

        while True:
            opciones = self._opciones()
            console.print("\n[bold]Menú principal[/bold]")
            for clave, (texto, _) in opciones.items():
                console.print(f"  [cyan]{clave}[/cyan]. {texto}")
            console.print("  [cyan]n[/cyan]. Página siguiente    [cyan]p[/cyan]. Página anterior")
            if self.estado.hay_filtros:
                console.print(f"[dim]Filtros activos: {escape(self.estado.descripcion_filtros)}[/dim]")

            eleccion = Prompt.ask(
                "Elige una opción", choices=[*opciones.keys(), "n", "p"], default="1"
            )

            if eleccion == "0":
                console.print("[bold cyan]¡Hasta luego![/bold cyan]")
                break
            elif eleccion == "n":
                self.accion_pagina(+1)
            elif eleccion == "p":
                self.accion_pagina(-1)
            else:
                opciones[eleccion][1]()  # type: ignore[misc]


def menu_principal() -> None:
    Interfaz(GestorAplicacionesWindows()).ejecutar()

def main() -> None:
    if platform.system() != "Windows":
        console.print(Panel("[red]Esta herramienta solo funciona en Windows.[/red]"))
        sys.exit(1)

    try:
        menu_principal()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/yellow]")
        sys.exit(0)
    except Exception:
        logger.exception("Error inesperado en la aplicación")
        donde = f" ({escape(str(LOG_FILE))})" if LOG_FILE else ""
        console.print(f"[red]Ocurrió un error inesperado. Revisa el archivo de log{donde} para más detalles.[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()