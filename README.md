# Basic Network Sniffer

A professional educational network packet analysis application built with Python and a React dashboard.

## Overview

Basic Network Sniffer is designed for cybersecurity students, network engineers, and beginners who want to understand how packets travel on a network. The project captures traffic on an authorized interface, parses packet metadata, identifies common protocols, and presents the information through a clean browser dashboard.

## Features

- Detect and list available network interfaces
- Start/stop live capture on a selected interface
- Parse IPv4, IPv6, TCP, UDP, ICMP, and DNS metadata
- Inspect recent packets in a table-based traffic dashboard
- Filter captured packets by protocol, address, port, or DNS query
- Expand packet rows to inspect common header metadata and a short payload hex preview
- Export captured packet metadata as downloadable CSV or JSON
- Clear in-memory packet history when capture is stopped
- A lightweight PCAP/PCAPNG file validation stub (offline parsing is not implemented yet)

## Architecture

- Backend: FastAPI + Scapy + Python
- Frontend: React + Vite
- Storage: in-memory live capture records with JSON/CSV API exports
- Testing: pytest

## Installing

1. Clone the repository
2. Create a virtual environment and install dependencies

```bash
cd /home/momye/Videos/network-sniffer/network_sniffer
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## Running the backend

```bash
cd /home/momye/Videos/network-sniffer/network_sniffer
. .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Running the frontend

```bash
cd /home/momye/Videos/network-sniffer/network_sniffer/frontend
npm install
npm run dev -- --host 0.0.0.0
```

Then open the frontend in the browser at:

- http://127.0.0.1:5173

## Testing

```bash
cd /home/momye/Videos/network-sniffer/network_sniffer
. .venv/bin/activate
pytest -q
```

## Permissions and legal use

This project is intended for authorized network diagnostics and educational use only. Capture traffic only on interfaces you own or are explicitly permitted to monitor. Do not run packet capture on public or shared networks without authorization.

## Troubleshooting

### Missing dependencies

If imports fail, recreate the virtual environment and reinstall:

```bash
rm -rf .venv
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

### Permission denied during capture

- Run the application with elevated privileges when required on Linux systems
- Ensure the interface is valid and permissions allow capture
- On Kali Linux, the packet capture privileges may require root or group membership such as wireshark

### Interface not listed

- Confirm the interface exists with `ip link` or `ifconfig`
- Ensure the OS exposes network interfaces to the user session

### Browser cannot reach the API

- Confirm the backend is running on port 8000
- Check that the frontend is pointing at the correct API URL in [frontend/src/App.jsx](frontend/src/App.jsx)

## Current limitations

- Captured packets are kept in memory and are lost when the backend restarts.
- Packet history is kept in memory and is lost when the backend restarts.
- The packet table displays captured records from the current backend process; very large sessions may use significant memory.
- PCAP import currently validates the file extension and reports file metadata; it does not parse packets from the file.
- Capture requires appropriate OS permissions. Capture errors raised asynchronously by Scapy may not be reported accurately by the API yet.

## Manual testing instructions

1. Select an authorized interface from the dashboard.
2. Start a short capture session.
3. Generate a small amount of traffic such as browsing or pinging a local host.
4. Review the packet listing and protocol summary.
5. Stop the capture, then optionally export the visible session as CSV or JSON or clear its in-memory history.

## Notes

This is an educational MVP. Persistent history, offline PCAP parsing, and real-time packet graphs remain future improvements. It does not decrypt TLS traffic.

# network_sniffer
A Python-based network packet sniffer for capturing and analyzing network traffic, identifying protocols, displaying source and destination IP addresses, and inspecting packet headers and payloads for educational network security analysis. Python ,Scapy, Networking ,Cybersecurity ,Packet Analysis, TCP/IP
