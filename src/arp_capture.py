import struct
import threading
from scapy.all import sniff, ARP
from collections import defaultdict
from models.models import Alert

class ARPMonitor:
    def __init__(self, iface = r"\Device\NPF_{29B0E055-8CC6-45F8-9B28-B0BD0B88F134}"):
        self.iface = iface
        self.ip_mac_table = {}
        self.alerts = []
    def _process_arp(self, packet):
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:
                ip = arp.psrc
                mac = arp.hwsrc

            if ip in self.ip_mac_table:
                if self.ip_mac_table[ip] != mac:
                    alert = Alert(
                        severity="HIGH",
                        reason = f"ARP spoof? {ip} changed MAC {self.ip_mac_table[ip]} → {mac}",
                        packet=None
                    )
                    self.alerts.append(alert)
                    print(f"⚠ ARP SPOOF DETECTED: {ip} was {self.ip_mac_table[ip]} now {mac}")
                else:
                    self.ip_mac_table[ip] = mac
    def start(self):
        sniff(iface=self.iface, filter="arp", prn = self._process_arp, store =0)
    
    def start_async(self):
        t = threading.Thread(target = self.start, daemon=True)
        t.start()