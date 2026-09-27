"""
Gestor de Aplicaciones - Windows
=================================

Herramienta de línea de comandos para listar y desinstalar aplicaciones
instaladas en Windows, leyendo el registro en tres ubicaciones:

    - HKLM, vista de 64 bits  (apps nativas de 64 bits)
    - HKLM, vista de 32 bits  (apps de 32 bits / WOW6432Node)
    - HKCU                    (apps instaladas solo para el usuario actual)

Dependencias:
    pip install rich

Uso:
    python gestor_aplicaciones.py
"""

from __future__ import annotations

import csv
import ctypes
import logging
import platform
import subprocess
import sys
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import winreg
except ImportError:  # No estamos en Windows
    winreg = None  # type: ignore

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "gestor_aplicaciones.log"


def configurar_logging() -> logging.Logger:
    """Configura un logger con rotación de archivo para trazabilidad."""
    LOG_DIR.mkdir(exist_ok=True)

    logger = logging.getLogger("gestor_aplicaciones")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:  # Evita duplicar handlers si el módulo se recarga
        handler = RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(funcName)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = configurar_logging()
console = Console()


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

    @property
    def comando_desinstalacion(self) -> Optional[str]:
        """Prioriza la desinstalación silenciosa (QuietUninstallString) si existe."""
        return self.quiet_uninstall_string or self.uninstall_string


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
        self._cache: List[Aplicacion] = []

    # -- Ubicaciones a inspeccionar ---------------------------------------- #

    @staticmethod
    def _ubicaciones() -> List[Tuple[int, int, str]]:
        """(hive, flags_wow64, etiqueta) para cada ubicación del registro a escanear."""
        return [
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "HKLM64"),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "HKLM32"),
            (winreg.HKEY_CURRENT_USER, 0, "HKCU"),
        ]

    @staticmethod
    def _leer_valor(clave, nombre: str, por_defecto=None):
        try:
            return winreg.QueryValueEx(clave, nombre)[0]
        except OSError:
            return por_defecto

    def _leer_aplicacion(
        self, hive: int, flags: int, etiqueta: str, subclave_nombre: str
    ) -> Optional[Aplicacion]:
        """Lee los valores de una subclave y construye un Aplicacion, o None si no aplica."""
        ruta_completa = f"{self.RUTA_DESINSTALACION}\\{subclave_nombre}"
        try:
            with winreg.OpenKey(hive, ruta_completa, 0, winreg.KEY_READ | flags) as clave_app:
                nombre = self._leer_valor(clave_app, "DisplayName")
                if not nombre:
                    return None  # Sin nombre visible: no es una app "real"

                es_componente = bool(self._leer_valor(clave_app, "SystemComponent", 0))
                if es_componente and not self.incluir_componentes_sistema:
                    return None

                return Aplicacion(
                    nombre=nombre,
                    origen=etiqueta,
                    version=self._leer_valor(clave_app, "DisplayVersion"),
                    publisher=self._leer_valor(clave_app, "Publisher"),
                    fecha_instalacion=self._leer_valor(clave_app, "InstallDate"),
                    tamanio_kb=self._leer_valor(clave_app, "EstimatedSize"),
                    uninstall_string=self._leer_valor(clave_app, "UninstallString"),
                    quiet_uninstall_string=self._leer_valor(clave_app, "QuietUninstallString"),
                    es_componente_sistema=es_componente,
                )
        except OSError as exc:
            logger.debug("No se pudo leer %s (%s): %s", subclave_nombre, etiqueta, exc)
            return None

    # -- API pública --------------------------------------------------------- #

    def listar_aplicaciones(self, forzar_actualizacion: bool = False) -> List[Aplicacion]:
        """Escanea el registro (con caché) y devuelve la lista de aplicaciones instaladas."""
        if self._cache and not forzar_actualizacion:
            return self._cache

        aplicaciones: List[Aplicacion] = []
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

                    identificador = (app.nombre, app.origen)
                    if identificador in vistos:
                        continue
                    vistos.add(identificador)
                    aplicaciones.append(app)
            finally:
                winreg.CloseKey(clave_raiz)

        aplicaciones.sort(key=lambda a: a.nombre.lower())
        self._cache = aplicaciones
        logger.info("Escaneo completado: %d aplicaciones encontradas.", len(aplicaciones))
        return aplicaciones

    def buscar_aplicaciones(self, consulta: str) -> List[Aplicacion]:
        """Filtra la lista de aplicaciones por coincidencia parcial de nombre."""
        consulta = consulta.strip().lower()
        return [a for a in self.listar_aplicaciones() if consulta in a.nombre.lower()]

    def desinstalar(self, app: Aplicacion) -> bool:
        """Ejecuta el comando de desinstalación asociado a la aplicación."""
        comando = app.comando_desinstalacion
        if not comando:
            logger.error("'%s' no tiene comando de desinstalación registrado.", app.nombre)
            console.print(f"[red]No se encontró un comando de desinstalación para «{app.nombre}».[/red]")
            return False

        logger.info("Iniciando desinstalación de '%s' (%s): %s", app.nombre, app.origen, comando)
        console.print(Panel(f"[cyan]Ejecutando:[/cyan] {comando}", title=f"Desinstalando {app.nombre}"))

        try:
            resultado = subprocess.run(comando, shell=True)
        except Exception as exc:
            logger.exception("Error al ejecutar el desinstalador de '%s'", app.nombre)
            console.print(f"[red]Error al ejecutar el desinstalador: {exc}[/red]")
            return False

        exito = resultado.returncode == 0
        if exito:
            logger.info("Desinstalación de '%s' finalizada (código %d).", app.nombre, resultado.returncode)
            console.print(f"[green]«{app.nombre}» se desinstaló correctamente.[/green]")
            self._cache = []  # invalidar caché para reflejar el cambio
        else:
            logger.warning("Desinstalador de '%s' devolvió código %d.", app.nombre, resultado.returncode)
            console.print(
                f"[yellow]El proceso terminó con código {resultado.returncode}. "
                "Puede que se haya cancelado o requiera revisión manual.[/yellow]"
            )
        return exito

    def exportar_csv(self, ruta: Path) -> None:
        """Exporta la lista actual de aplicaciones a un archivo CSV."""
        apps = self.listar_aplicaciones()
        with ruta.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Nombre", "Versión", "Editor", "Origen", "Fecha instalación", "Tamaño (KB)"])
            for a in apps:
                writer.writerow(
                    [a.nombre, a.version or "", a.publisher or "", a.origen,
                     a.fecha_instalacion or "", a.tamanio_kb or ""]
                )
        logger.info("Lista exportada a %s (%d aplicaciones).", ruta, len(apps))


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

def mostrar_tabla(apps: List[Aplicacion]) -> None:
    tabla = Table(title="Aplicaciones instaladas", box=box.ROUNDED, header_style="bold cyan")
    tabla.add_column("#", justify="right", style="dim")
    tabla.add_column("Nombre", style="bold")
    tabla.add_column("Versión")
    tabla.add_column("Editor")
    tabla.add_column("Origen", justify="center")

    for i, app in enumerate(apps, start=1):
        tabla.add_row(str(i), app.nombre, app.version or "-", app.publisher or "-", app.origen)

    console.print(tabla)


def texto_toggle_componentes(incluir: bool) -> str:
    return ("Ocultar" if incluir else "Mostrar") + " componentes del sistema"


def menu_principal() -> None:
    console.print(
        Panel.fit(
            """[bold cyan]
               _____                    _ _        
              |_   _|__ _ __ _ __ ___ (_) |_ __ _ 
                | |/ _ \ '__| '_ ` _ \| | __/ _` |
                | |  __/ |  | | | | | | | || (_| |
                |_|\___|_|  |_| |_| |_|_|\__\__,_|
            Consulta y desinstala programas instalados desde el registro.
            """,
        )
    )

    if not es_admin():
        console.print(
            "[yellow]⚠ No se está ejecutando como administrador. "
            "Algunas desinstalaciones podrían fallar o pedir permisos elevados.[/yellow]\n"
        )

    gestor = GestorAplicacionesWindows()
    apps_actuales: List[Aplicacion] = []

    while True:
        opciones = {
            "1": "Listar todas las aplicaciones",
            "2": "Buscar una aplicación",
            "3": "Desinstalar una aplicación",
            "4": "Exportar lista a CSV",
            "5": texto_toggle_componentes(gestor.incluir_componentes_sistema),
            "0": "Salir",
        }

        console.print("\n[bold]Menú principal[/bold]")
        for clave, texto in opciones.items():
            console.print(f"  [cyan]{clave}[/cyan]. {texto}")

        eleccion = Prompt.ask("Elige una opción", choices=list(opciones.keys()), default="1")

        if eleccion == "1":
            with console.status("Escaneando el registro..."):
                apps_actuales = gestor.listar_aplicaciones()
            mostrar_tabla(apps_actuales)

        elif eleccion == "2":
            consulta = Prompt.ask("Nombre (o parte del nombre) a buscar")
            apps_actuales = gestor.buscar_aplicaciones(consulta)
            if apps_actuales:
                mostrar_tabla(apps_actuales)
            else:
                console.print("[yellow]No se encontraron coincidencias.[/yellow]")

        elif eleccion == "3":
            if not apps_actuales:
                with console.status("Escaneando el registro..."):
                    apps_actuales = gestor.listar_aplicaciones()
                mostrar_tabla(apps_actuales)

            indice = IntPrompt.ask("Número de la aplicación a desinstalar (0 para cancelar)")
            if indice == 0:
                continue

            app = apps_actuales[indice - 1] if 1 <= indice <= len(apps_actuales) else None
            if app is None:
                console.print("[red]Número fuera de rango.[/red]")
                continue

            if Confirm.ask(f"¿Confirmas que quieres desinstalar «{app.nombre}»?", default=False):
                gestor.desinstalar(app)
                apps_actuales = []  # forzar re-escaneo la próxima vez

        elif eleccion == "4":
            ruta = Path(Prompt.ask("Ruta del archivo CSV", default="aplicaciones_instaladas.csv"))
            try:
                gestor.exportar_csv(ruta)
                console.print(f"[green]Exportado correctamente a {ruta.resolve()}[/green]")
            except OSError as exc:
                logger.exception("Error exportando a CSV")
                console.print(f"[red]No se pudo exportar: {exc}[/red]")

        elif eleccion == "5":
            gestor.incluir_componentes_sistema = not gestor.incluir_componentes_sistema
            with console.status("Actualizando lista..."):
                apps_actuales = gestor.listar_aplicaciones(forzar_actualizacion=True)
            estado = "incluidos" if gestor.incluir_componentes_sistema else "ocultos"
            console.print(f"[cyan]Componentes del sistema {estado}.[/cyan]")

        elif eleccion == "0":
            console.print("[bold cyan]¡Hasta luego![/bold cyan]")
            break


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
        console.print("[red]Ocurrió un error inesperado. Revisa el archivo de log para más detalles.[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()