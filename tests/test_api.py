from fastapi.testclient import TestClient

from app.main import app, capture_manager


client = TestClient(app)


def setup_function():
    capture_manager.stop()
    capture_manager.clear()


def test_packet_api_omits_raw_bytes_and_exports_json_and_csv():
    capture_manager.packets.append(
        {
            "timestamp": "2026-10-27T12:00:00+00:00",
            "protocol": "TCP",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "raw_bytes": b"private payload bytes",
        }
    )

    packet_response = client.get("/api/packets")
    json_response = client.get("/api/packets/export?format=json")
    csv_response = client.get("/api/packets/export?format=csv")

    assert packet_response.status_code == 200
    assert "raw_bytes" not in packet_response.json()[0]
    assert "private payload bytes" not in json_response.text
    assert csv_response.status_code == 200
    assert "protocol" in csv_response.text


def test_clear_packets_endpoint():
    capture_manager.packets.append({"protocol": "UDP"})

    response = client.post("/api/packets/clear")

    assert response.status_code == 200
    assert response.json()["status"] == "cleared"
    assert capture_manager.packets == []


def test_export_rejects_unknown_format():
    response = client.get("/api/packets/export?format=pcap")

    assert response.status_code == 400