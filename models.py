from dataclasses import dataclass, field
from datetime import datetime
@dataclass
class Packet:
    protocol:str
    src_ip:str
    dst_ip:str
    src_port:int|None
    dst_port:int|None
    ttl:int
    size:int
    raw:bytes

@dataclass
class Alert:
    severity: str
    reason: str
    packet:Packet
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))