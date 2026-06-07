# SLCYD
A raw socket network packet sniffer with a live terminal UI Captures and decodes TCP/UDP/ICMP traffic in real time and flags suspicious network patterns.

i ( and claude tbh ) built it from scratch in python lol

---

## Features

- Raw socket capture
- Protocol decoding
- Live terminal UI
- Suspicious pattern detection
    - DNS queries to non-gateway servers
    - Traffic on known malware ports (4444,1337,31337)
    - Port scan detection

---

## Requirements
 
- Python 3.10+
- Windows (raw sockets use `SIO_RCVALL`)
- Must be run as Administrator

---

## How it works

every network packet has layers of headers wrapping the actual data:
```
[ IP Header | TCP/UDP/ICMP Header | Data ]
```

SLCYD opens a raw socket, intercepts packets before OS processes them and manually unpacks each header using Python's struct module to read the binary fields.

the analyzer tracks patterns over time, building a map of which IPs are hitting which ports, watching for DNS queries going outside your router and flagging known bad ports.
