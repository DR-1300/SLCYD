import socket
import struct
from pkt_parser import parse_packet
from ui import make_table, add_packet_row, console,add_alert_row
from rich.live import Live
from analyser import Analyzer

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

class Sniffer:
    def __init__(self, gateway_ip = "192.168.1.1"): # dont get too excited, this is a private IP and every home router uses it LOL
        self.host = get_local_ip()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind((self.host,0))
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.analyzer = Analyzer(gateway_ip="192.168.1.1")
    def start(self):
        table = make_table()
        with Live(table, refresh_per_second=4, screen=True):
            while True:
                raw_data, addr = self.sock.recvfrom(65535)
                packet = parse_packet(raw_data)
                add_packet_row(table, packet)
                alert = self.analyzer.analyze(packet)
                if alert:
                    add_alert_row(table, alert)

if __name__ == "__main__":
    s = Sniffer()
    s.start()