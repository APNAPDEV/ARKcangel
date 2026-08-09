# ==============================================================================
# Proyecto: Nebula
# Autor: APNAPDEV
# Repositorio Oficial: https://github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================
# NEBULA— Centro de Herramientas (versión corregida)
# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027
import os
import sys
import time
import math
import socket
import subprocess
import platform
import re 

# Windows-specific (Termita usa winreg Importante si qiereis modificar algo ternerlo en cuenta.) https://github.com/Babyhamsta/Aimmy/tree/Aimmy-V1/models
try:
    import winreg
except Exception:
    winreg = None

# utilities
import colorama
colorama.init(autoreset=True)


# Rich imports (UI bonito o eso espero)
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn #No tocar!!!!!!!!!!!!!!
from rich.table import Table
from rich import box

console = Console()

# Logo ASCII centrado no se ni como(Rich)

LOGO_ASCII = r"""
███╗   ██╗███████╗██████╗  ██╗   ██╗  ██╗      █████╗ 
████╗  ██║██╔════╝██╔══██╗ ██║   ██║  ██║     ██╔══██╗
██╔██╗ ██║█████╗  ██████╔╝ ██║   ██║  ██║     ███████║
██║╚██╗██║██╔══╝  ██╔══██╗ ██║   ██║  ██║     ██╔══██║
██║ ╚████║███████╗██████╔╝ ███████╔╝  ███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝╚═════╝   ╚═════╝   ╚══════╝╚═╝  ╚═╝ 
"""

def show_logo(duration=1.2, fps=12):  # No cambiar esta formula la direfencia DE FPS CON LA DURACIÓN AFECTA AL MUESTRE POR PANTALLA!!!
    
    """
    Muestra el logo ASCII centrado y con cambios de color a demas de un "pulso" por llamarlo de laguna manera.
    """
    palette = ["#a020f0", "#00ffff", "#1e90ff"]  # morado -> celeste -> azul
    frames = int(duration * fps)

    def hex_to_rgb(h): return tuple(int(h[i:i+2], 16) for i in (1, 3, 5))
    rgb_colors = [hex_to_rgb(c) for c in palette]

    try:
        with Live(console=console, refresh_per_second=fps) as live:
            for step in range(frames):
                # calcula color interpolado
                a = step % len(rgb_colors)
                p = (a + 1) % len(rgb_colors)
                n = abs(math.sin(step * 0.28))
                a2 = int(rgb_colors[a][0] * (1 - n) + rgb_colors[p][0] * n)
                p2 = int(rgb_colors[a][1] * (1 - n) + rgb_colors[p][1] * n)
                s = int(rgb_colors[a][2] * (1 - n) + rgb_colors[p][2] * n)
                color = f"#{a2:02x}{p2:02x}{s:02x}"

                # pulso de tamaño
                pulse = (math.sin(step * 0.25) + 1) / 2  # 0..1
                pad_lr = 6 + int(3 * pulse)

                # construiremos el panel con logo coloreado
                logo_colored = f"[bold {color}]{LOGO_ASCII}[/bold {color}]"
                footer = "[bright_white]Centro de Herramientas — APNAPDEV © 2026/2027[/bright_white]"
                content = logo_colored + "\n" + footer

                border = "bright_magenta" if (step // 5) % 2 == 0 else "cyan"
                panel = Panel(
                    Align.center(content, vertical="middle"),
                    border_style=border,
                    padding=(1, pad_lr),
                )
                live.update(panel)
                time.sleep(1 / fps)
    except Exception as e:
        # Si Live falla me cago en todo 
        console.print(f"[yellow]Advertencia: no se pudo usar Live ({e}). Mostrando logo estático.[/yellow]")
        console.print(Panel(Align.center(LOGO_ASCII + "\nCentro de Herramientas — APNAPDEV © 2025"), border_style="magenta"))

    console.clear()
    console.print(
        Panel(
            Align.center("[bold cyan]NEBULA[/bold cyan]\n[green]¡Listo para operar![/green]", vertical="middle"),
            border_style="bright_green",
            padding=(1, 8),
        )
    )
    time.sleep(0.8)
    console.clear()

#------------------------------------------------------------------------------------
#-------------------------------- |Nebula Cipher v2| --------------------------------
#------------------------------------------------------------------------------------
# Alfabeto dinámico A-Z basado en clave (funciona porfavor)


import random
import string

ALFABETO = string.ascii_uppercase
SIMBOLOS = "@!?$%&#87462<>*/  "


def normalizar(texto: str) -> str:
    return texto.upper()


def clave_a_semilla(clave: str) -> int:
    clave = normalizar(clave)
    return sum(ord(c) for c in clave)


def generar_tabla_cifrado(clave: str) -> dict:
    """
    Genera una tabla A-Z única basada en la clave
    """
    semilla = clave_a_semilla(clave)
    random.seed(semilla)

    pool = list(ALFABETO + SIMBOLOS)
    random.shuffle(pool)

    tabla = {}
    usados = set()

    for letra in ALFABETO:
        for c in pool:
            if c not in usados:
                tabla[letra] = c
                usados.add(c)
                break

    return tabla


def invertir_tabla(tabla: dict) -> dict:
    return {v: k for k, v in tabla.items()}


def cifrar_nebula(texto: str, clave: str) -> str:
    texto = normalizar(texto)
    tabla = generar_tabla_cifrado(clave)

    resultado = ""
    for c in texto:
        if c in ALFABETO:
            resultado += tabla[c]
        else:
            resultado += c

    return resultado


def descifrar_nebula(texto: str, clave: str) -> str:
    tabla = generar_tabla_cifrado(clave)
    tabla_inv = invertir_tabla(tabla)

    resultado = ""
    for c in texto:
        if c in tabla_inv:
            resultado += tabla_inv[c]
        else:
            resultado += c

    return resultado



def nebula_cipher_menu():
    console.print(
        Panel(
            "[bold cyan]Nebula Cipher v2[/bold cyan]\n"
            "[dim]Cifrado simétrico con alfabeto dinámico basado en clave[/dim]",
            border_style="magenta"
        )
    )

    console.print("[1] Encriptar palabra")
    console.print("[2] Desencriptar palabra")
    console.print("[ENTER] Volver")

    opt = console.input("\nOpción: ")

    if opt == "1":
        texto = console.input("Texto a encriptar: ")
        clave = console.input("Clave secreta: ")
        res = cifrar_nebula(texto, clave)
        console.print(Panel(f"[green]Resultado:[/green]\n{res}", border_style="green"))

    elif opt == "2":
        texto = console.input("Texto encriptado: ")
        clave = console.input("Clave secreta: ")
        res = descifrar_nebula(texto, clave)
        console.print(Panel(f"[green]Resultado:[/green]\n{res}", border_style="green"))


#------------------------------------------------------------------------------------
#-------------------------------- |Port Scanner| ------------------------------------
#------------------------------------------------------------------------------------

def port_scanner_rich(target: str, limit: int = 200):
    """
    Escanea puertos 1..limit sobre target mostrando una barra de progreso con Rich
    y una tabla con puertos abiertos al finalizar Y YA ESTA NADA MÁS
    """
    console.print(f"\n[bold cyan]Escaneando puertos de {target} (1–{limit})[/bold cyan]\n")

    open_ports = []
    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Escaneando...", total=limit)
            for port in range(1, limit + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.22)
                try:
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(port)
                except Exception:
                    pass
                finally:
                    s.close()
                progress.advance(task)
    except KeyboardInterrupt:
        console.print("\n[yellow]Escaneo interrumpido por el usuario.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error durante el escaneo: {e}[/red]")

    console.print("\n[bold green]Escaneo completado.[/bold green]\n")

    if open_ports:
        table = Table(title=f"Puertos abiertos en {target}", header_style="bold magenta", box=box.SIMPLE)
        table.add_column("Puerto", style="cyan", justify="center")
        table.add_column("Estado", style="green", justify="center")
        for p in open_ports:
            table.add_row(str(p), "[bold green]Abierto[/bold green]")
        console.print(table)
    else:
        console.print("[yellow]No se encontraron puertos abiertos.[/yellow]")




#------------------------------------------------------------------------------------
#-------------------------------- |TERMITA <3| --------------------------------------
#------------------------------------------------------------------------------------
# Termita carrito (¿Si estas leyendo esto significa que mi app es conocida?)

def listar_aplicaciones_windows():
    """Devuelve lista de DisplayName instaladas en Windows (si es posible si no te jodes)."""
    aplicaciones = []
    if winreg is None:
        return aplicaciones
    try:
        clave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    except Exception:
        return aplicaciones
    try:
        for i in range(winreg.QueryInfoKey(clave)[0]):
            try:
                subclave = winreg.EnumKey(clave, i)
                subclave_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\' + subclave
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subclave_path) as app_clave:
                    try:
                        nombre = winreg.QueryValueEx(app_clave, 'DisplayName')[0]
                        aplicaciones.append(nombre)
                    except Exception:
                        continue
            except Exception:
                continue
    finally:
        try:
            winreg.CloseKey(clave)
        except Exception:
            pass
    return aplicaciones

def desinstalar_aplicacion_windows(nombre_aplicacion):
    """Intentar desinstalar la app buscando su UninstallString (Windows solo por el momento)."""
    if winreg is None:
        console.print(Panel("[yellow]Función de desinstalación solo disponible en Windows.[/yellow]"))
        return False
    try:
        clave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    except Exception:
        console.print("[red]No se pudo acceder al registro de Windows.[/red]")
        return False
    try:
        for i in range(winreg.QueryInfoKey(clave)[0]):
            try:
                subclave = winreg.EnumKey(clave, i)
                subclave_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\' + subclave
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subclave_path) as app_clave:
                    try:
                        nombre = winreg.QueryValueEx(app_clave, 'DisplayName')[0]
                    except Exception:
                        continue
                    if nombre == nombre_aplicacion:
                        try:
                            uninstall_string = winreg.QueryValueEx(app_clave, 'UninstallString')[0]
                        except Exception:
                            console.print("[red]No se encontró la cadena de desinstalación para esta app.[/red]")
                            return False
                        console.print(Panel(f"[cyan]Ejecutando desinstalador:[/cyan] {uninstall_string}"))
                        subprocess.call(uninstall_string, shell=True)
                        return True
            except Exception:
                continue
    finally:
        try:
            winreg.CloseKey(clave)
        except Exception:
            pass
    return False


#------------------------------------------------------------------------------------
#-------------------------------- |Tracer Driver| -----------------------------------
#------------------------------------------------------------------------------------
def tracerdriver_rich():
    console.print(Panel("[bold]TracerDriver — Drivers activos[/bold]", border_style="magenta"))
    try:
        res = subprocess.run(['driverquery'], capture_output=True, text=True, check=True)
        console.print(Panel(res.stdout, title="driverquery output", subtitle="(presiona ENTER para volver)", padding=(1,1)))
    except subprocess.CalledProcessError as e:
        console.print(Panel(f"[red]Error al listar drivers: {e}[/red]"))

#------------------------------------------------------------------------------------
#-------------------------------- |Smart IP| ----------------------------------------
#------------------------------------------------------------------------------------

def smart_ip_rich():
    console.print(Panel("[bold cyan]Smart_IP — Dispositivos en la red[/bold cyan]"))
    try:
        salida = subprocess.check_output("arp -a", shell=True, text=True)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return
    ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", salida)
    ips = sorted(set(ips))
    table = Table(title="Dispositivos ARP", box=box.SIMPLE)
    table.add_column("IP", style="cyan")
    table.add_column("Tipo estimado", style="magenta")
    for ip in ips:
        table.add_row(ip, "Desconocido")
    console.print(table)
    # permitir inspección por IP
    if ips:
        choice = console.input("[green]Introduce una IP para escanear con nmap (ENTER para skip): [/green]")
        if choice.strip():
            console.print(Panel(f"[cyan]Escaneando {choice} con nmap (si está disponible)...[/cyan]"))
            try:
                out = subprocess.check_output(f"nmap -O {choice}", shell=True, text=True, stderr=subprocess.DEVNULL, timeout=30)
                console.print(Panel(out, title=f"nmap {choice}"))
            except Exception as e:
                console.print(f"[yellow]nmap no disponible o escaneo falló: {e}[/yellow]")

def mostrar_arp():
    try:
        salida = subprocess.check_output("arp -a", shell=True, text=True)
        print(colorama.Fore.GREEN + salida + colorama.Style.RESET_ALL)
    except Exception as e:
        print(colorama.Fore.RED + f"Error al obtener ARP: {e}" + colorama.Style.RESET_ALL)

def show_netstat():
    os.system("netstat -ano")

def ping_host(host):
    # simple forward to system ping (cross-platform flag)
    param = "-n" if platform.system().lower() == "windows" else "-c"
    os.system(f"ping {param} 4 {host}")

def show_wifi_password():
    # intenta mostrar perfiles (Windows solo, ya quelinux es tajo complicao)
    if platform.system().lower() != "windows":
        print("Función disponible solo en Windows.")
        return
    try:
        res = subprocess.run(["netsh", "wlan", "show", "profile"], capture_output=True, text=True)
        print(res.stdout)
        wifi = input("Nombre del WiFi a inspeccionar (copiar como aparece arriba): ")
        res2 = subprocess.run(["netsh", "wlan", "show", "profile", f'name=\"{wifi}\"', "key=clear"], capture_output=True, text=True)
        print(res2.stdout)
    except Exception as e:
        print(colorama.Fore.RED + f"Error: {e}" + colorama.Style.RESET_ALL)

def ip_scanner_rich():
    console.print(Panel("[bold cyan]IP Scanner[/bold cyan]"))
    try:
        salida = subprocess.check_output("arp -a", shell=True, text=True)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return
    rows = []
    for line in salida.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:.-]+)\s+(\S+)", line)
        if match:
            rows.append(match.groups())
    if rows:
        table = Table(title="Tabla ARP", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("Tipo", style="green")
        for ip, mac, kind in rows:
            table.add_row(ip, mac, kind)
        console.print(table)#
    else:
        console.print(Panel(salida, title="ARP raw"))

#------------------------------------------------------------------------------------
#-------------------------------- |Network Pinger|-- --------------------------------
#------------------------------------------------------------------------------------

def network_pinger_rich(host):
    from rich.status import Status
    with console.status(f"[bold cyan]Haciendo ping a {host}...[/bold cyan]", spinner="dots"):
        try:
            # cross-platform: build ping command
            param = "-n" if platform.system().lower() == "windows" else "-c"
            res = subprocess.run(f"ping {param} 4 {host}", shell=True, capture_output=True, text=True, check=True, timeout=15)
            console.print(Panel(res.stdout, title=f"Ping {host}"))
        except subprocess.CalledProcessError:
            console.print(Panel(f"[red]No fue posible hacer ping a {host}[/red]"))
        except Exception as e:
            console.print(f"[yellow]Error: {e}[/yellow]")


#------------------------------------------------------------------------------------
#-------------------------------- |Active Connections| --------------------------------
#------------------------------------------------------------------------------------

def active_connections_rich():
    console.print(Panel("[bold cyan]Conexiones activas (netstat)[/bold cyan]"))
    try:
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=True)
        console.print(Panel(res.stdout, title="netstat -ano (presiona ENTER para volver)"))
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


#------------------------------------------------------------------------------------
#----------------------------- |Internal Network Password| --------------------------
#------------------------------------------------------------------------------------

def internal_network_password_rich():
    while True:
            try:
                
                result = subprocess.run(["netsh", "wlan", "show", "profile"], capture_output=True, text=True)
                print(colorama.Fore.BLUE + result.stdout + colorama.Style.RESET_ALL)

                wifi_name = input(colorama.Fore.YELLOW + "Ingrese el WiFi a escanear: " + colorama.Style.RESET_ALL)

                result = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f'name="{wifi_name}"', "key=clear"],
                    capture_output=True, text=True, check=True  # check=True lanza un error si falla
                )

                print(colorama.Fore.GREEN + result.stdout + colorama.Style.RESET_ALL)
                break  

            except subprocess.CalledProcessError:
                print(colorama.Fore.RED + "¡Nombre incorrecto o perfil no disponible!" + colorama.Style.RESET_ALL)
                print("Asegúrese de escribir el nombre exactamente como aparece en la lista.\n")
            except Exception as e:
                print(colorama.Fore.RED + "Ocurrió un error inesperado:" + colorama.Style.RESET_ALL)
                print(f"{e}\n")

#------------------------------------------------------------------------------------
#-------------------------------- |IP MANAGER| --------------------------------------
#------------------------------------------------------------------------------------

def ip_manager_rich():
    console.print(Panel("[bold cyan]IP Manager[/bold cyan]"))
    console.print("[1] Mostrar información IP\n[2] Liberar y renovar IP\n[ENTER] Cancelar")
    o = console.input("Opción: ")
    if o == "1":
        res = subprocess.run(["ipconfig"], capture_output=True, text=True)
        console.print(Panel(res.stdout, title="ipconfig"))
    elif o == "2":
        # confirmar con console input
        confirm = console.input("[red]¿Seguro que quieres liberar y renovar la IP? (y/N): [/red]")
        if confirm.lower() == "y":
            console.print("[yellow]Liberando...[/yellow]")
            subprocess.run(["ipconfig", "/release"])
            console.print("[yellow]Renovando...[/yellow]")
            subprocess.run(["ipconfig", "/renew"])
            console.print("[green]Hecho.[/green]")



#------------------------------------------------------------------------------------
#-------------------------------- |Shutdown & Restart| ------------------------------
#------------------------------------------------------------------------------------

def shutdown_restart_rich():
    console.print(Panel("[bold magenta]Apagar / Reiniciar[/bold magenta]"))
    console.print("[1] Apagar\n[2] Reiniciar\n[ENTER] Cancelar")
    opt = console.input("Opción: ")
    if opt == "1":
        confirm = console.input("[red]¿Apagar ahora? (y/N): [/red]")
        if confirm.lower() == "y":
            console.print("[yellow]Apagando...[/yellow]")
            os.system("shutdown /s /t 0")
    elif opt == "2":
        confirm = console.input("[red]¿Reiniciar ahora? (y/N): [/red]")
        if confirm.lower() == "y":
            console.print("[yellow]Reiniciando...[/yellow]")
            os.system("shutdown /r /t 0")


# Menú principal (Mira yo no se de rich un dia funciono y ahi lo deje, si funciona no lo cambies)

def main_menu():
    os.system("title NEBULA - Centro de Herramientas")
    while True:
        # NEBULA_menu_rich.py
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        from rich.align import Align
        import time
        import math

        console = Console()

        def animated_menu():
            """Menú principal animado estilo retro con Rich"""
            base_menu = [
                "╔═══════════════════════════════════════════════════════════════════════════════╗",
                "║               ───────────────────────────────────────────                     ║",
                "║ 1. >> Termita                                7. >> Network_pinger             ║",
                "║ 2. >> Tracerdriver                           8. >> Active_connections         ║",
                "║ 3. >> Smart_IP                               9. >> Internal Network Password  ║",
                "║ 4. >> Nebula_Cypher                          10. >> IP_Manager                ║",
                "║ 5. >> Port_Scanner                           11. >> Shutdown/restart          ║",
                "║ 6. >> IP_scanner                                                          *   ║",
                "║                                                                               ║",
                "║    *     x      ───────────────────────────────────────────     +    *        ║",
                "║ 12. Exit                                                 NEBULA: V4.0.0       ║",
                "║ 13. Info                                                 V:Español            ║",
                "╚═══════════════════════════════════════════════════════════════════════════════╝",
            ]

            # Definimos colores que ciclan para los bordes y texto
            palette = ["#a020f0", "#00ffff", "#1e90ff"]  # morado → celeste → azul

            # función para interpolar color
            def color_cycle(step, colors):
                def hex_to_rgb(h): return tuple(int(h[i:i+2], 16) for i in (1, 3, 5))
                rgb_colors = [hex_to_rgb(c) for c in colors]
                i = step % len(rgb_colors)
                j = (i + 1) % len(rgb_colors)
                t = abs(math.sin(step * 0.3))
                r = int(rgb_colors[i][0] * (1 - t) + rgb_colors[j][0] * t)
                g = int(rgb_colors[i][1] * (1 - t) + rgb_colors[j][1] * t)
                b = int(rgb_colors[i][2] * (1 - t) + rgb_colors[j][2] * t)
                return f"#{r:02x}{g:02x}{b:02x}"

            console.clear()
            for step, line in enumerate(base_menu):
                border_color = color_cycle(step, palette)
                text = Text(line, style=f"bold {border_color}")
                console.print(Align.center(text))
                time.sleep(0.05)

            console.print(
                Panel(
                    Align.center(
                        "[bright_white]Selecciona una opción para comenzar[/bright_white]\n"
                        "[dim]Escribe el número y presiona ENTER[/dim]",
                        vertical="middle",
                    ),
                    border_style="cyan",
                    padding=(1, 6),
                )
            )
        animated_menu()

        try:
            choice = int(input(colorama.Fore.GREEN + "Selecciona una opción: " + colorama.Style.RESET_ALL))
        except ValueError:
            print(colorama.Fore.RED + "Entrada no válida. Introduce el número de opción." + colorama.Style.RESET_ALL)
            continue

        if choice == 1:
            console.print(Panel("[bold]Termita — Desinstalar aplicaciones (Windows)[/bold]", border_style="magenta"))
            apps = listar_aplicaciones_windows()
            if not apps:
                console.print("[yellow]No se encontraron aplicaciones o no se tiene acceso al registro.[/yellow]")
                input("ENTER para volver...")
                continue
            # imprimir con numbering
            for idx, a in enumerate(apps, 1):
                print(f"{idx}. {a}")
            try:
                app_num = int(input(colorama.Fore.YELLOW + "Ingrese el número de la aplicación a desinstalar (0 cancelar): " + colorama.Style.RESET_ALL))
            except ValueError:
                console.print("[red]Entrada inválida.[/red]")
                input("ENTER para volver...")
                continue
            if app_num <= 0 or app_num > len(apps):
                console.print("[yellow]Operación cancelada o número fuera de rango.[/yellow]")
                input("ENTER para volver...")
                continue
            app_name = apps[app_num - 1]
            confirm = console.input(f"[red]¿Desinstalar '{app_name}'? (y/N): [/red]")
            if confirm.lower() == "y":
                ok = desinstalar_aplicacion_windows(app_name)
                if ok:
                    console.print(Panel(f"[green]{app_name} desinstalada.[/green]"))
                else:
                    console.print(Panel(f"[red]No se pudo desinstalar {app_name}.[/red]"))
            else:
                console.print("[yellow]Desinstalación cancelada.[/yellow]")
            input("ENTER para volver...")

        elif choice == 2:
            tracerdriver_rich()
            input("ENTER para volver...")

        elif choice == 3:
            smart_ip_rich()
            input("ENTER para volver...")

        elif choice == 4:
            nebula_cipher_menu()
            input("ENTER para volver...")


        elif choice == 5:
            target = input("Introduce la IP a escanear: ")
            try:
                limit = int(input("Número de puertos a escanear (ej: 200): "))
            except ValueError:
                console.print("[yellow]Número inválido, se usarán 200 puertos.[/yellow]")
                limit = 200
            port_scanner_rich(target, limit)
            input("ENTER para volver...")

        elif choice == 6:
            ip_scanner_rich()
            input("ENTER para volver...")

        elif choice == 7:
            host = input("IP o dominio: ")
            network_pinger_rich(host)
            input("ENTER para volver...")

        elif choice == 8:
            active_connections_rich()
            input("ENTER para volver...")

        elif choice == 9:
            internal_network_password_rich()
            input("ENTER para volver...")

        elif choice == 10:
            ip_manager_rich()
            input("ENTER para volver...")

        elif choice == 11:
            shutdown_restart_rich()
            input("ENTER para volver...")

        elif choice == 12:
            s = input("¿Seguro que quieres salir? (Y/n): ")
            if s.lower() in ("y", "yes", "s"):
                console.print("[green]Cerrando NEBULA. ¡Hasta luego![/green]")
                break

        elif choice == 13:
            console.print(Panel("""\
────────────── "Info" ──────────────
- Termita: Lista apps instaladas para su desintalación(Windows).       
- TracerDriver: Lista drivers activos.
- Smart_IP: Muestra ARP local.
- Nebula_Chyper: Cada clave genera su propio patrón de cifrado.
- Port_Scanner: Escanea puertos (interfaz Rich).
- IP_scanner: Lista IPs conectadas.
- Network_pinger: Hace ping a host.
- Active_connections: Mostrar netstat.
- Internal network password: Mostrar perfiles Wi-Fi (Windows).
- IP_Manager: ipconfig /release & /renew.
- Shutdown/restart: Apagar o reiniciar.
                                
            -Developer APNAPDEV-        #App made by Adrian C. — APNAPDEV © 2026/2027
────────────────────────────────────
""", title="Info", border_style="cyan"))
            input("ENTER para volver...")
        else:
            console.print("[red]Opción no válida.[/red]")

if __name__ == "__main__":
    
    try:
        show_logo()
    except Exception as e:
        print("No se pudo mostrar la intro Rich:", e)
    # Ejecuta menú principal y eso es todo
    main_menu()

