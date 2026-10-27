from __future__ import annotations

import socket

from scapy.all import get_if_addr, get_if_hwaddr, get_if_list


def list_network_interfaces() -> list[dict[str, str | bool | list[str]]]:
    """Return a list of interfaces with their names and addresses."""
    interfaces: list[dict[str, str | bool | list[str]]] = []
    for name in get_if_list():
        try:
            ip_address = get_if_addr(name)
        except Exception:
            ip_address = ""

        try:
            mac_address = get_if_hwaddr(name)
        except Exception:
            mac_address = ""

        interfaces.append(
            {
                "name": name,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "is_active": bool(ip_address),
                "aliases": [name],
            }
        )
    return interfaces


def get_interface_ip(interface: str) -> str:
    try:
        return get_if_addr(interface)
    except Exception:
        return ""


def get_host_name() -> str:
    return socket.gethostname()
