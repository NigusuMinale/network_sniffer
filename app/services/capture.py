from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from scapy.all import Packet, sniff

from app.services.parser import analyze_packet


class CaptureManager:
    def __init__(self) -> None:
        self.packets: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._error: str | None = None
        self._started_at: float | None = None
        self._interface: str | None = None

    def start(
        self,
        interface: str,
        packet_limit: int = 100,
        duration: float = 10.0,
        bpf_filter: str | None = None,
        packet_callback: Callable[[Packet], None] | None = None,
    ) -> None:
        if not interface:
            raise ValueError("A network interface must be selected before capture starts.")
        if packet_limit < 1:
            raise ValueError("Packet limit must be at least 1.")
        if duration <= 0:
            raise ValueError("Capture duration must be greater than 0.")
        if self._thread and self._thread.is_alive():
            raise RuntimeError("A capture is already running.")

        self._stop_event.clear()
        self._error = None
        self._started_at = time.time()
        self._interface = interface

        def _worker() -> None:
            try:
                count = 0
                deadline = self._started_at + duration

                def _on_packet(pkt: Packet) -> None:
                    nonlocal count
                    if self._stop_event.is_set():
                        raise KeyboardInterrupt

                    record = analyze_packet(pkt)
                    record["interface"] = interface
                    with self._lock:
                        self.packets.append(record)
                    count += 1
                    if packet_callback is not None:
                        packet_callback(pkt)
                    if packet_limit and count >= packet_limit:
                        self._stop_event.set()

                while not self._stop_event.is_set() and time.time() < deadline:
                    sniff(
                        iface=interface,
                        filter=bpf_filter,
                        prn=_on_packet,
                        store=False,
                        timeout=min(1.0, max(0.01, deadline - time.time())),
                        stop_filter=lambda _packet: self._stop_event.is_set(),
                    )
            except Exception as exc:
                self._error = str(exc)
            finally:
                self._stop_event.set()

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def clear(self) -> None:
        with self._lock:
            self.packets.clear()

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(packet) for packet in self.packets]

    def status(self) -> dict[str, Any]:
        with self._lock:
            packet_count = len(self.packets)
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "packet_count": packet_count,
            "created_at": self._started_at,
            "interface": self._interface,
            "error": self._error,
        }
