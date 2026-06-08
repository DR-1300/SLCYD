import socket
import struct
from models.models import Packet
def parse_ip_header(raw_data):
    iph = struct.unpack('! B  B   H   H   H   B   B   H   4s  4s', raw_data[:20])
    print(f"full iph tuple: {iph}")
    ttl = iph[5]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa((iph[9]))
    ip_header_length = (iph[0] & 0xF)*4
    return ttl, protocol, src_ip, dst_ip, ip_header_length
def parse_tcp(data):
    tcp = struct.unpack('! H H L L B B H H H', data[:20])
    src_port = tcp[0]
    dst_port = tcp[1]
    window_size = tcp[6]
    return src_port, dst_port, window_size
def parse_udp(data):
    udp = struct.unpack('! H H H H', data[:8])
    src_port = udp[0]
    dst_port = udp[1]
    return src_port, dst_port
def parse_packet(raw_data):
    ttl, protocol, src_ip, dst_ip, ip_header_length = parse_ip_header(raw_data)
    segment = raw_data[ip_header_length:]
    os_guess = None
    if int(protocol)== 6:
        src_port, dst_port, window_size = parse_tcp(segment)
        proto_name = "TCP"
        os_guess = fingerprint_os(ttl, window_size)
    elif protocol ==17:
        src_port, dst_port = parse_udp(segment)
        proto_name = "UDP"
        os_guess = fingerprint_os(ttl, None)  
    elif protocol==1:
        src_port, dst_port = None, None
        proto_name="ICMP"
        os_guess = fingerprint_os(ttl, None)  
    else:
        src_port, dst_port = None, None
        proto_name="OTHER"
        os_guess = fingerprint_os(ttl, None)  
    
    return Packet(
        protocol=proto_name,
        src_ip = src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ttl=ttl,
        size=len(raw_data),
        raw=raw_data,
        os_guess=os_guess
    )

def fingerprint_os(ttl: int, window_size:int | None):
    if ttl<=64:
        base_os = "Linux/macOS"
    elif ttl<=128:
        base_os="Windows"
    elif ttl<=255:
        base_os = "Cisco"
    else:
        base_os = "Unknown"
    
    if base_os == "Linux/macOS":
        if window_size == 65535:
            return "macOS"
        else:
            return "Linux"
    if base_os=="Windows":
        return "Windows"
    elif base_os == "Cisco":
        return "Cisco/Network Device"
    else:
        return "Unknown"