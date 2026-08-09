# ==============================================================================
# Proyecto: HORIZON
# Autor: APNAPDEV
# Repositorio Oficial: https://github.com/APNAPDEV/ARKcangel
# Licencia: GNU GPLv3
#
# Queda prohibida la redistribución o presentación de este código como propio
# sin la debida atribución y enlace al repositorio original.
# ==============================================================================

# Autor original: Adrian C. — APNAPDEV © 2023-2026/2027

"""
Argus - Monitor de tráfico de red en terminal
Compatible con Windows (y Linux/Mac con pequeños ajustes de permisos)

Requisitos:
    pip install psutil rich
    (opcional, para captura de paquetes y DNS) pip install scapy
    En Windows, scapy necesita Npcap instalado: https://npcap.com/#download!!!!!!!!
    (marca la opción "WinPcap API-compatible mode" al instalar)

Ejecuta la terminal como Administrador para desbloquear:
    - Ver el proceso dueño de TODAS las conexiones (no solo las tuyas)
    - Captura de paquetes (DNS + tráfico por proceso), vía scapy/Npcap
"""

import argparse
import json
import os
import socket
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
port_to_pid = {}                                   # puerto local -> pid (se refresca cada ciclo)
proc_traffic = defaultdict(lambda: {"sent": 0, "recv": 0})  # pid -> bytes acumulados (vía captura)
local_ips = set()
lock = threading.Lock()


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



def main():
    parser = argparse.ArgumentParser(description="Argus - Monitor de tráfico de red")
    parser.add_argument("--interval", type=float, default=2.0, help="Segundos entre refrescos")
    parser.add_argument("--no-capture", action="store_true", help="Desactiva captura de paquetes (DNS y tráfico por proceso)")
    args = parser.parse_args()

    load_known_ips()
    global local_ips
    local_ips = get_local_ips()

    capture_active = SCAPY_AVAILABLE and not args.no_capture

    console.print(Panel.fit(
        """[bold cyan]
██╗  ██   ████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗
██║  ██║██╔═══██╗██╔══██╗██║╚══███╔╝██╔═══██╗████╗  ██║
███████║██║   ██║██████╔╝██║  ███╔╝ ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║██╔══██╗██║ ███╔╝  ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
 H O R I Z O N  ·  v1.0  S C A N N I N G
 [/bold cyan] 
 
 - Monitor de tráfico de red\n"""
        f"IPs conocidas cargadas: {len(known_ips)}\n"
        f"Captura de paquetes (DNS + tráfico por proceso): {'activa' if capture_active else 'inactiva'}\n"
        "[dim]Ctrl+C para salir. Al salir se te preguntará si quieres guardar las IPs nuevas como conocidas.[/dim]",
        border_style="green"
    ))
    time.sleep(1.5)

    if capture_active:
        t = threading.Thread(target=packet_capture_thread, daemon=True)
        t.start()

    prev_counters = psutil.net_io_counters()
    layout = build_layout()

    try:
        with Live(layout, refresh_per_second=1, console=console):
            while True:
                layout["connections"].update(build_connections_table())
                bw_panel, prev_counters = build_bandwidth_panel(prev_counters, args.interval)
                layout["bandwidth"].update(bw_panel)
                layout["dns"].update(build_dns_panel())
                layout["proc_traffic"].update(build_process_traffic_panel())
                time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[bold]Saliendo de Argus...[/bold]")
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