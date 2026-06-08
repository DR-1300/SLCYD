import argparse
from src.capture import Sniffer
from src.arp_capture import ARPMonitor
def parse_args():
    parser = argparse.ArgumentParser(description= "SLCYD - Network Packet Sniffer")
    parser.add_argument("--gateway", type=str, default="192.168.1.1", help="Your router IP")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"Starting SLCYD | Gateway: {args.gateway}")
    monitor = ARPMonitor()
    monitor.start_async()
    sniffer = Sniffer(gateway_ip=args.gateway)
    sniffer.start()