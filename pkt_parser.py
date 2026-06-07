import socket
import struct
from models import Packet
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
    return src_port, dst_port
def parse_udp(data):
    udp = struct.unpack('! H H H H', data[:8])
    src_port = udp[0]
    dst_port = udp[1]
    return src_port, dst_port
def parse_packet(raw_data):
    ttl, protocol, src_ip, dst_ip, ip_header_length = parse_ip_header(raw_data)
    segment = raw_data[ip_header_length:]

    if int(protocol)== 6:
        src_port, dst_port = parse_tcp(segment)
        proto_name = "TCP"
    elif protocol ==17:
        src_port, dst_port = parse_udp(segment)
        proto_name = "UDP"
    elif protocol==1:
        src_port, dst_port = None, None
        proto_name="ICMP"
    else:
        src_port, dst_port = None, None
        proto_name="OTHER"
    
    return Packet(
        protocol=proto_name,
        src_ip = src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ttl=ttl,
        size=len(raw_data),
        raw=raw_data
    )