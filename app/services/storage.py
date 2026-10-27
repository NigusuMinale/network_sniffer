from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable


def export_packets_json(records: Iterable[dict[str, Any]], path: str | Path) -> Path:
    output_path = Path(path)
    output_path.write_text(json.dumps(list(records), indent=2), encoding="utf-8")
    return output_path


def export_packets_csv(records: Iterable[dict[str, Any]], path: str | Path) -> Path:
    output_path = Path(path)
    rows = list(records)
    fieldnames = sorted({key for row in rows for key in row.keys()})

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return output_path


def import_pcap_file(path: str | Path) -> list[dict[str, Any]]:
    import os

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    if not file_path.name.lower().endswith((".pcap", ".pcapng")):
        raise ValueError("Unsupported capture format. Expected .pcap or .pcapng")

    return [{"source": str(file_path), "size_bytes": os.path.getsize(file_path), "status": "imported"}]
