import argparse
from src.capture import Sniffer
def parse_args():
    parser = argparse.ArgumentParser(description= "SLCYD - Network Packet Sniffer")
    parser.add_argument("--gateway", type=str, default="192.168.1.1", help="Your router IP")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"Starting SLCYD | Gateway: {args.gateway}")
    sniffer = Sniffer(gateway_ip=args.gateway)
    sniffer.start()
