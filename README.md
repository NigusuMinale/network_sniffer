# Basic Network Sniffer

A Python/React educational packet-analysis dashboard for learning how network traffic and common protocols work. Use it only on networks you own or are authorized to monitor.

## Features

- Discover network interfaces and start or stop a live capture.
- Parse IPv4, IPv6, TCP, UDP, ICMP, and DNS packet metadata.
- Search packets by address, port, or DNS query and filter by protocol.
- Expand packet rows to inspect header metadata and a short payload hex preview.
- Download captured metadata as CSV or JSON, or clear stopped-session history.
- Apply an optional BPF capture filter.

## Technology

- Backend: Python, FastAPI, and Scapy
- Frontend: React and Vite
- Tests: pytest

## Requirements

- Python 3.14 or another version supported by the pinned packages
- Node.js and npm
- Appropriate operating-system permissions for packet capture

## Setup

Run these commands from the repository root. Create and activate a virtual environment, then install the Python dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

Install frontend dependencies:

```bash
cd frontend
npm install
```

## Run

Start the backend from the repository root in one terminal. Running Uvicorn through the virtual-environment Python ensures it uses the project dependencies rather than system packages:

```bash
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the frontend from the `frontend` directory in another terminal:

```bash
npm run dev
```

Open http://127.0.0.1:5173. The dashboard expects the API at http://127.0.0.1:8000 by default. To use another API address, set `VITE_API_BASE` before starting Vite.

## Tests and production build

From the repository root, run backend tests:

```bash
.venv/bin/python -m pytest -q
```

Build the frontend:

```bash
cd frontend
npm run build
```

## Troubleshooting

### Uvicorn imports the wrong packages

Activate `.venv` and run `python -m uvicorn ...`, or use `.venv/bin/python -m uvicorn ...`. Avoid launching the system `uvicorn` executable outside the project environment.

### Capture permission denied

Capture may require elevated privileges or platform-specific packet-capture permissions. Configure permissions for the intended interface; do not broaden permissions unnecessarily.

### No interface appears

Check that the operating system exposes the interface (for example, with `ip link`) and that the backend starts without import errors.

## Limitations

- Packet history is held in memory and is lost when the backend restarts.
- Large captures can consume substantial memory.
- PCAP/PCAPNG import is not implemented; the existing helper only checks file metadata.
- TLS payloads are not decrypted. The payload preview only shows bytes Scapy exposes as packet payload.
- Live capture requires authorization and suitable OS permissions.

## Responsible use

This tool is for education and authorized diagnostics. Capture only traffic on networks and interfaces you own or have explicit permission to monitor. Respect privacy, organizational policies, and applicable law.
