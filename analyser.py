from collections import defaultdict
from datetime import datetime
from models import Packet, Alert

SUS_PORTS = {4444,1337,31337,9001,6667}

class Analyzer:
    def __init__(self, gateway_ip:str):
        self.gateway_ip = gateway_ip
        self.ip_port_map = defaultdict(set)
        self.ip_packet_count = defaultdict(int)
    def analyze(self, packet:Packet):
        checks = [
            self._check_sus_port,
            self._check_dns_hijack,
            self._check_port_scan,
        ]
        for check in checks:
            alert = check(packet)
            if alert:
                return alert
        return None
    def _check_sus_port(self, packet:Packet):
        if packet.dst_port in SUS_PORTS:
           return Alert(
            severity="HIGH",
            reason=f"Suspicious port {packet.dst_port}",
            packet=packet )
        return None
    def _check_dns_hijack(self, packet:Packet):
        if packet.protocol == "UDP" and packet.dst_port == 53 and packet.dst_ip != self.gateway_ip:
            return Alert(
                severity="MEDIUM",
                reason=f"DNS query to non-gateway {packet.dst_ip}",
                packet=packet )
        return None
    def _check_port_scan(self, packet: Packet):
        if packet.dst_port is not None:
            self.ip_port_map[packet.src_ip].add(packet.dst_port)
            if len(self.ip_port_map[packet.src_ip])>10:
                return Alert(
                    severity="HIGH",
                    reason=f"Port scan from {packet.src_ip} ({len(self.ip_port_map[packet.src_ip])} ports)",
                    packet = packet
                )
        return None