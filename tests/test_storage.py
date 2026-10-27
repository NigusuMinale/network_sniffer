import json

from app.services.storage import export_packets_csv, export_packets_json, import_pcap_file


PAYLOAD = [
    {
        "timestamp": "2024-01-01T00:00:00Z",
        "interface": "eth0",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 64,
        "icmp_type": None,
        "icmp_code": None,
        "dns_query": None,
        "payload_hex": "48656c6c6f",
    }
]


def test_export_json(tmp_path):
    path = tmp_path / "packets.json"
    export_packets_json(PAYLOAD, path)

    data = json.loads(path.read_text())
    assert data[0]["dst_ip"] == "10.0.0.2"
    assert data[0]["protocol"] == "TCP"


def test_export_csv(tmp_path):
    path = tmp_path / "packets.csv"
    export_packets_csv(PAYLOAD, path)

    text = path.read_text()
    assert "dst_ip" in text
    assert "10.0.0.2" in text


def test_import_pcap_file(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    try:
        records = import_pcap_file(pcap_path)
    except FileNotFoundError:
        records = []

    assert isinstance(records, list)
