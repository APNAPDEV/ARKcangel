# ==============================================================================
# Proyecto: HORIZON
# Autor: APNAPDEV
# Repositorio Oficial: github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================

# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027

"""
Horizon - Monitor de tráfico de red en terminal, con bandeja del sistema
Compatible con Windows (y Linux/Mac con pequeños ajustes de permisos)

Requisitos:
    pip install psutil rich pystray pillow plyer
    (opcional, para captura de paquetes y DNS) pip install scapy
    En Windows, scapy necesita Npcap instalado: https://npcap.com/#download
    (marca la opción "WinPcap API-compatible mode" al instalar)

Ejecuta la terminal como Administrador para desbloquear:
    - Ver el proceso dueño de TODAS las conexiones (no solo las tuyas)
    - Captura de paquetes (DNS + tráfico por proceso), vía scapy/Npcap

Bandeja del sistema:
    - Click derecho en el icono de la bandeja para Mostrar/Ocultar la consola,
      guardar las IPs conocidas al vuelo, o salir de forma segura.
    - El núcleo (captura, detección de IPs nuevas, alertas) sigue funcionando
      aunque la ventana esté oculta; solo se pausa el redibujado en pantalla.
"""

import argparse
import ctypes
import json
import os
import socket
import sys
import threading
import time
from collections import deque, defaultdict
from datetime import datetime

import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# --- Bandeja del sistema (opcional, requiere pystray + pillow) ---
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception:
    TRAY_AVAILABLE = False

# --- Notificaciones nativas de Windows (opcional, requiere plyer) ---
try:
    from plyer import notification as toast
    PLYER_AVAILABLE = True
except Exception:
    PLYER_AVAILABLE = False

# --- Captura de paquetes / DNS (opcional, requiere scapy + Npcap en Windows) ---
try:
    from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

console = Console()

KNOWN_IPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_ips.json")

# --- Estado compartido entre hilos ---
hostname_cache = {}
dns_log = deque(maxlen=15)
known_ips = set()
new_ips_this_session = set()
alerted_ips = set()                                 # para no repetir notificación por la misma IP
port_to_pid = {}                                   # puerto local -> pid (se refresca cada ciclo)
proc_traffic = defaultdict(lambda: {"sent": 0, "recv": 0})  # pid -> bytes acumulados (vía captura)
local_ips = set()
lock = threading.Lock()

# --- Estado de bandeja / visibilidad ---
app_visible = True          # si la consola está mostrándose o escondida
should_exit = threading.Event()   # se activa desde el menú "Salir de forma segura"
console_hwnd = None
latest_panels = {"connections": None, "bandwidth": None, "dns": None, "proc_traffic": None}

SW_HIDE = 0
SW_SHOW = 5
CONSOLE_TITLE = f"Horizon-{os.getpid()}"   # título único para localizar la ventana real, sea cual sea el host


def get_console_hwnd():
    """
    Obtiene el handle de la ventana de consola VISIBLE de verdad.

    En Windows 11, los programas de consola suelen abrirse dentro de Windows
    Terminal (no en conhost.exe clásico). Ahí, GetConsoleWindow() devuelve un
    handle "fantasma" que usa ConPTY internamente — no la ventana que ves ni
    la que aparece en la barra de tareas, que pertenece a un proceso aparte
    (WindowsTerminal.exe). Por eso ocultar ese handle no tenía ningún efecto
    visible.

    En su lugar, ponemos un título único a la consola y buscamos la ventana
    top-level real con ese título — esto funciona igual en conhost clásico
    y en Windows Terminal (con la configuración por defecto).
    """
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(CONSOLE_TITLE)
        time.sleep(0.15)  # da tiempo a que el título se propague a la ventana visible
        hwnd = ctypes.windll.user32.FindWindowW(None, CONSOLE_TITLE)
        if hwnd:
            return hwnd
        # Fallback: método clásico, por si corre en conhost puro sin Windows Terminal
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        return hwnd if hwnd else None
    except Exception:
        return None


def set_console_visibility(show: bool):
    """Muestra u oculta la ventana de consola vía la API de Windows (ctypes puro)."""
    global console_hwnd
    if console_hwnd is None:
        console_hwnd = get_console_hwnd()
    if not console_hwnd:
        return
    try:
        ctypes.windll.user32.ShowWindow(console_hwnd, SW_SHOW if show else SW_HIDE)
    except Exception:
        pass


def send_toast(title, message):
    """Envía una notificación nativa de Windows si plyer está disponible. No bloqueante."""
    if not PLYER_AVAILABLE:
        return

    def worker():
        try:
            toast.notify(title=title, message=message, app_name="Horizon", timeout=6)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()


def get_local_ips():
    ips = set()
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except Exception:
        pass
    ips.add("127.0.0.1")
    return ips


def load_known_ips():
    global known_ips
    if os.path.exists(KNOWN_IPS_FILE):
        try:
            with open(KNOWN_IPS_FILE, "r") as f:
                known_ips = set(json.load(f))
        except Exception:
            known_ips = set()


def save_known_ips():
    try:
        with open(KNOWN_IPS_FILE, "w") as f:
            json.dump(sorted(known_ips), f, indent=2)
    except Exception:
        pass


def resolve_hostname(ip):
    """Reverse DNS con cache, para no bloquear la tabla en cada refresco."""
    if ip in hostname_cache:
        return hostname_cache[ip]
    hostname_cache[ip] = "..."  # placeholder mientras se resuelve

    def worker():
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = "-"
        hostname_cache[ip] = name

    threading.Thread(target=worker, daemon=True).start()
    return hostname_cache[ip]


def get_process_name(pid):
    if pid is None:
        return "-"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return f"pid:{pid}"


def is_private_ip(ip):
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("172.3")
        or ip.startswith("127.")
        or ip == "0.0.0.0"
        or ip == "::"
    )


def build_connections_table(show_dns_col=True):
    table = Table(title="Conexiones activas", expand=True, show_lines=False)
    table.add_column("Proceso", style="cyan", no_wrap=True)
    table.add_column("IP remota", style="white")
    if show_dns_col:
        table.add_column("Host (reverse DNS)", style="magenta")
    table.add_column("Puerto", justify="right")
    table.add_column("Estado", style="green")
    table.add_column("Nueva", justify="center")

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        table.add_row("Ejecuta como Administrador para ver todos los procesos", "", "", "", "", "")
        return table

    # Refrescamos el mapa puerto local -> pid, usado por el capturador de paquetes
    # para poder atribuir tráfico a procesos concretos.
    new_map = {}
    for c in conns:
        if c.laddr and c.pid:
            new_map[c.laddr.port] = c.pid
    with lock:
        port_to_pid.clear()
        port_to_pid.update(new_map)

    rows = []
    for c in conns:
        if not c.raddr:
            continue
        ip = c.raddr.ip
        port = c.raddr.port
        proc_name = get_process_name(c.pid)
        status = c.status

        is_new = False
        with lock:
            if ip not in known_ips and not is_private_ip(ip):
                is_new = True
                new_ips_this_session.add(ip)
                if ip not in alerted_ips:
                    alerted_ips.add(ip)
                    send_toast(
                        "Horizon · IP nueva detectada",
                        f"{proc_name} → {ip}:{port}"
                    )

        row = [proc_name, ip]
        if show_dns_col:
            row.append(resolve_hostname(ip) if not is_private_ip(ip) else "(LAN)")
        row.append(str(port))
        row.append(status)
        row.append("🆕" if is_new else "")
        rows.append((is_new, row))

    # Nuevas primero, para que salten a la vista
    rows.sort(key=lambda r: not r[0])
    for is_new, row in rows[:25]:
        style = "bold yellow" if is_new else None
        table.add_row(*row, style=style)

    if not rows:
        table.add_row("Sin conexiones salientes activas", "", "", "", "", "") if not show_dns_col \
            else table.add_row("Sin conexiones salientes activas", "", "", "", "", "")

    return table


def build_bandwidth_panel(prev, interval):
    current = psutil.net_io_counters()
    sent_rate = (current.bytes_sent - prev.bytes_sent) / interval
    recv_rate = (current.bytes_recv - prev.bytes_recv) / interval

    def fmt(rate):
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if rate < 1024:
                return f"{rate:.1f} {unit}"
            rate /= 1024
        return f"{rate:.1f} TB/s"

    text = Text()
    text.append("⬆ Subida: ", style="bold")
    text.append(f"{fmt(sent_rate)}\n", style="green")
    text.append("⬇ Bajada: ", style="bold")
    text.append(f"{fmt(recv_rate)}\n", style="cyan")
    text.append(f"\nTotal enviado: {current.bytes_sent / (1024**2):.1f} MB\n")
    text.append(f"Total recibido: {current.bytes_recv / (1024**2):.1f} MB")

    return Panel(text, title="Ancho de banda", border_style="blue"), current


def build_dns_panel():
    text = Text()
    if not SCAPY_AVAILABLE:
        text.append("scapy/Npcap no disponible.\n", style="dim")
        text.append("Instala Npcap (npcap.com) y 'pip install scapy',\n", style="dim")
        text.append("y ejecuta como Administrador, para ver aquí las\n", style="dim")
        text.append("consultas DNS en vivo (confirma que AdGuard/WARP\nprocesan tus consultas).", style="dim")
    else:
        with lock:
            entries = list(dns_log)
        if not entries:
            text.append("Esperando consultas DNS...", style="dim")
        else:
            for ts, domain in reversed(entries):
                text.append(f"[{ts}] ", style="dim")
                text.append(f"{domain}\n", style="white")
    return Panel(text, title="Consultas DNS recientes", border_style="magenta")


def build_process_traffic_panel():
    table = Table(title="Tráfico por proceso (vía captura, requiere admin)", expand=True)
    table.add_column("Proceso", style="cyan", no_wrap=True)
    table.add_column("Enviado", justify="right", style="green")
    table.add_column("Recibido", justify="right", style="cyan")

    def fmt(b):
        for unit in ["B", "KB", "MB", "GB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    with lock:
        snapshot = dict(proc_traffic)

    if not snapshot:
        table.add_row("Esperando tráfico...", "", "")
        return Panel(table, border_style="yellow")

    rows = []
    for pid, counts in snapshot.items():
        rows.append((get_process_name(pid), counts["sent"], counts["recv"], counts["sent"] + counts["recv"]))
    rows.sort(key=lambda r: r[3], reverse=True)

    for name, sent, recv, _ in rows[:12]:
        table.add_row(name, fmt(sent), fmt(recv))

    return Panel(table, border_style="yellow")


def packet_capture_thread():
    """
    Un unico hilo de captura que:
    1) Registra consultas DNS salientes.
    2) Atribuye bytes de cada paquete IP al proceso dueno del puerto local
       (cruzando con port_to_pid, que se refresca cada ciclo desde psutil).
    Requiere permisos elevados (Admin en Windows) y Npcap instalado.
    """
    def handle_packet(pkt):
        # --- DNS ---
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                domain = str(pkt[DNSQR].qname)
            ts = datetime.now().strftime("%H:%M:%S")
            with lock:
                dns_log.append((ts, domain))

        # --- Trafico por proceso ---
        if not pkt.haslayer(IP):
            return
        size = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        sport = dport = None
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            return

        is_outbound = src_ip in local_ips
        local_port = sport if is_outbound else dport

        with lock:
            pid = port_to_pid.get(local_port)
            if pid:
                if is_outbound:
                    proc_traffic[pid]["sent"] += size
                else:
                    proc_traffic[pid]["recv"] += size

    try:
        sniff(filter="ip", prn=handle_packet, store=False)
    except Exception as e:
        with lock:
            dns_log.append((datetime.now().strftime("%H:%M:%S"), f"[error captura: {e}]"))


def build_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="top", ratio=2),
        Layout(name="bottom", ratio=1),
    )
    layout["top"].split_row(
        Layout(name="connections", ratio=3),
        Layout(name="bandwidth", ratio=1),
    )
    layout["bottom"].split_row(
        Layout(name="dns", ratio=1),
        Layout(name="proc_traffic", ratio=1),
    )
    return layout


# ==============================================================================
# Módulo de Bandeja del Sistema (Capa de Control)
# ==============================================================================

def create_tray_image():
    """Genera un icono simple en memoria (no requiere ningún archivo .ico externo)."""
    img = Image.new("RGB", (64, 64), color=(10, 14, 25))
    draw = ImageDraw.Draw(img)
    draw.ellipse((6, 6, 58, 58), outline=(0, 200, 255), width=4)
    draw.ellipse((24, 24, 40, 40), fill=(0, 200, 255))
    return img


def _toggle_visibility(icon, item):
    global app_visible
    app_visible = not app_visible
    set_console_visibility(app_visible)


def _save_ips_now(icon, item):
    with lock:
        known_ips.update(new_ips_this_session)
    save_known_ips()
    send_toast("Horizon", "IPs conocidas guardadas correctamente.")


def _exit_safely(icon, item):
    should_exit.set()
    icon.stop()
    set_console_visibility(True)  # aseguramos que la consola vuelva a mostrarse al salir


def build_tray_icon():
    menu = pystray.Menu(
        pystray.MenuItem("Mostrar / Ocultar Horizon", _toggle_visibility, default=True),
        pystray.MenuItem("Guardar IPs actuales", _save_ips_now),
        pystray.MenuItem("Salir de forma segura", _exit_safely),
    )
    return pystray.Icon("horizon", create_tray_image(), "Horizon — Monitor de red", menu)


# ==============================================================================
# Núcleo Lógico (Operación Continua) — corre siempre, esté o no visible la consola
# ==============================================================================

def monitor_loop(interval):
    """
    Refresca conexiones, ancho de banda, DNS y tráfico por proceso en un ciclo
    independiente del renderizado. Esto es lo que se sigue ejecutando aunque la
    consola esté oculta: los datos nunca dejan de fluir, solo se deja de pintar.
    """
    prev_counters = psutil.net_io_counters()
    while not should_exit.is_set():
        conn_table = build_connections_table()
        bw_panel, prev_counters = build_bandwidth_panel(prev_counters, interval)
        dns_panel = build_dns_panel()
        proc_panel = build_process_traffic_panel()

        with lock:
            latest_panels["connections"] = conn_table
            latest_panels["bandwidth"] = bw_panel
            latest_panels["dns"] = dns_panel
            latest_panels["proc_traffic"] = proc_panel

        time.sleep(interval)



def main():
    parser = argparse.ArgumentParser(description="Horizon - Monitor de tráfico de red")
    parser.add_argument("--interval", type=float, default=2.0, help="Segundos entre refrescos")
    parser.add_argument("--no-capture", action="store_true", help="Desactiva captura de paquetes (DNS y tráfico por proceso)")
    parser.add_argument("--no-tray", action="store_true", help="Desactiva la bandeja del sistema (modo consola clásico)")
    args = parser.parse_args()

    load_known_ips()
    global local_ips, console_hwnd
    local_ips = get_local_ips()
    console_hwnd = get_console_hwnd()

    capture_active = SCAPY_AVAILABLE and not args.no_capture
    tray_active = TRAY_AVAILABLE and not args.no_tray

    console.print(Panel.fit(
        """[bold cyan]
██╗  ██╗ ██████╗ ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗
██║  ██║██╔═══██╗██╔══██╗██║╚══███╔╝██╔═══██╗████╗  ██║
███████║██║   ██║██████╔╝██║  ███╔╝ ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║██╔══██╗██║ ███╔╝  ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
 H O R I Z O N  ·  v1.0  S C A N N I N G
[/bold cyan]

Monitor de tráfico de red\n"""
        f"IPs conocidas cargadas: {len(known_ips)}\n"
        f"Captura de paquetes (DNS + tráfico por proceso): {'activa' if capture_active else 'inactiva'}\n"
        f"Bandeja del sistema: {'activa (click derecho en el icono)' if tray_active else 'inactiva'}\n"
        "[dim]Ctrl+C, o el menú de la bandeja, para salir de forma segura.[/dim]",
        border_style="green"
    ))
    time.sleep(1.5)

    if not TRAY_AVAILABLE and not args.no_tray:
        console.print("[dim]Bandeja no disponible: instala 'pystray' y 'pillow' para activarla.[/dim]")
    if not PLYER_AVAILABLE:
        console.print("[dim]Notificaciones no disponibles: instala 'plyer' para recibir alertas de IPs nuevas.[/dim]")

    if capture_active:
        threading.Thread(target=packet_capture_thread, daemon=True).start()

    # Hilo del núcleo lógico: sigue vivo esté o no visible la consola.
    threading.Thread(target=monitor_loop, args=(args.interval,), daemon=True).start()

    tray_icon = None
    if tray_active:
        tray_icon = build_tray_icon()
        threading.Thread(target=tray_icon.run, daemon=True).start()

    layout = build_layout()

    try:
        while not should_exit.is_set():
            if app_visible:
                # Estado Visible: se repinta la interfaz mientras el usuario esté mirando.
                with Live(layout, refresh_per_second=2, console=console) as live:
                    while app_visible and not should_exit.is_set():
                        with lock:
                            panels = dict(latest_panels)
                        if panels["connections"] is not None:
                            layout["connections"].update(panels["connections"])
                            layout["bandwidth"].update(panels["bandwidth"])
                            layout["dns"].update(panels["dns"])
                            layout["proc_traffic"].update(panels["proc_traffic"])
                        time.sleep(0.5)
            else:
                # Estado Oculto: no se gasta CPU redibujando; los datos siguen
                # acumulándose en monitor_loop() en segundo plano.
                time.sleep(0.5)
    except KeyboardInterrupt:
        should_exit.set()

    console.print("\n[bold]Saliendo de Horizon...[/bold]")
    if tray_icon:
        try:
            tray_icon.stop()
        except Exception:
            pass
    set_console_visibility(True)

    if new_ips_this_session:
        console.print(f"Se detectaron [yellow]{len(new_ips_this_session)}[/yellow] IPs nuevas esta sesión.")
        resp = console.input("¿Guardarlas como conocidas para no volver a resaltarlas? [s/N]: ")
        if resp.strip().lower() == "s":
            with lock:
                known_ips.update(new_ips_this_session)
            save_known_ips()
            console.print("[green]Guardado.[/green]")


if __name__ == "__main__":
    main()