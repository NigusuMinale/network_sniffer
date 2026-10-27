from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Raw, packet


def _safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    return getattr(obj, attr, default)


def analyze_packet(pkt: packet.Packet) -> dict[str, Any]:
    """Normalize a Scapy packet into a record-friendly dictionary."""
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interface": "",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "UNKNOWN",
        "length": len(pkt) if hasattr(pkt, "__len__") else 0,
        "ttl": None,
        "eth_src": None,
        "eth_dst": None,
        "icmp_type": None,
        "icmp_code": None,
        "dns_query": None,
        "payload_hex": "",
        "raw_bytes": None,
    }

    if pkt is None or not hasattr(pkt, "haslayer"):
        return record

    if pkt.haslayer("Raw"):
        payload = bytes(pkt["Raw"].load)
        record["payload_hex"] = payload.hex()
        record["raw_bytes"] = payload

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        record["src_ip"] = ip_layer.src
        record["dst_ip"] = ip_layer.dst
        record["ttl"] = getattr(ip_layer, "ttl", None)
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        record["src_ip"] = ip_layer.src
        record["dst_ip"] = ip_layer.dst
        record["ttl"] = getattr(ip_layer, "hlim", None)

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        record["src_port"] = tcp_layer.sport
        record["dst_port"] = tcp_layer.dport
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        record["src_port"] = udp_layer.sport
        record["dst_port"] = udp_layer.dport
    elif pkt.haslayer(ICMP):
        icmp_layer = pkt[ICMP]
        record["icmp_type"] = int(getattr(icmp_layer, "type", 0) or 0)
        record["icmp_code"] = int(getattr(icmp_layer, "code", 0) or 0)

    if pkt.haslayer(TCP):
        record["protocol"] = "TCP"
    elif pkt.haslayer(UDP):
        record["protocol"] = "UDP"
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    if pkt.haslayer(DNS):
        record["protocol"] = "DNS"
        dns_layer = pkt[DNS]
        if getattr(dns_layer, "qr", 0) == 0 and getattr(dns_layer, "qd", 0):
            qname = None
            qd = getattr(dns_layer, "qd", None)
            if qd is not None and hasattr(qd, "qname"):
                value = qd.qname
                qname = value.decode(errors="ignore") if isinstance(value, bytes) else str(value)
                if qname.endswith("."):
                    qname = qname[:-1]
            record["dns_query"] = qname

    if pkt.haslayer("Ether"):
        eth = pkt["Ether"]
        record["eth_src"] = getattr(eth, "src", None)
        record["eth_dst"] = getattr(eth, "dst", None)

    if pkt.haslayer(DNSQR):
        qd = pkt[DNSQR]
        qname = qd.qname.decode(errors="ignore") if isinstance(qd.qname, bytes) else str(qd.qname)
        if qname.endswith("."):
            qname = qname[:-1]
        record["dns_query"] = qname

    return record
