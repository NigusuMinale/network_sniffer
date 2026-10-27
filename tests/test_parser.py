from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, ICMP

from app.services.parser import analyze_packet


def test_ipv4_tcp_packet_parsing():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=443)
    record = analyze_packet(packet)

    assert record["src_ip"] == "192.168.1.10"
    assert record["dst_ip"] == "8.8.8.8"
    assert record["src_port"] == 12345
    assert record["dst_port"] == 443
    assert record["protocol"] == "TCP"


def test_ipv6_udp_packet_parsing():
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=53, dport=5353)
    record = analyze_packet(packet)

    assert record["src_ip"] == "2001:db8::1"
    assert record["dst_ip"] == "2001:db8::2"
    assert record["src_port"] == 53
    assert record["dst_port"] == 5353
    assert record["protocol"] == "UDP"


def test_dns_packet_parsing():
    packet = IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=5353, dport=53) / DNS(id=1, qr=0, qd=1) / DNSQR(qname="example.com")
    record = analyze_packet(packet)

    assert record["protocol"] == "DNS"
    assert record["dns_query"] == "example.com"


def test_icmp_packet_parsing():
    packet = IP(src="10.0.0.5", dst="10.0.0.1") / ICMP(type=8, code=0)
    record = analyze_packet(packet)

    assert record["protocol"] == "ICMP"
    assert record["icmp_type"] == 8
    assert record["icmp_code"] == 0
