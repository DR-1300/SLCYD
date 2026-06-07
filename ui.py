from rich.console import Console
from rich.table import Table
from rich.live import Live
from models import Packet

console = Console()

def make_table():
    table = Table(title = "SLCYD", border_style= "bright_blue")
    table.add_column("Protocol", style = "bold", width = 10)
    table.add_column("Source IP", width=18)
    table.add_column("Destination IP", width=18)
    table.add_column("Dst Port", width=10)
    table.add_column("Size", width=8)
    return table

def get_protocol_color(protocol):
    colors = {"TCP": "green", "UDP": "yellow", "ICMP": "cyan", "OTHER": "red"}
    return colors.get(protocol, "red")

def add_packet_row(table, packet: Packet):
    color = get_protocol_color(packet.protocol)
    port = str(packet.dst_port) if packet.dst_port else "-"
    table.add_row(
        f"[{color}]{packet.protocol}[/{color}]",
        packet.src_ip,
        packet.dst_ip,
        port,
        f"{packet.size} B"
    )
def add_alert_row(table, alert):
    table.add_row(
        f"[red]⚠ {alert.severity}[/red]",
        alert.packet.src_ip,
        alert.packet.dst_ip,
        str(alert.packet.dst_port) if alert.packet.dst_port else "-",
        f"[red]{alert.reason[:20]}[/red]"
    )
