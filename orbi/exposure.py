"""Remote-access watch: which devices on the home network accept remote-control connections.

A TCP connect to each port, from this PC, the same way another device in the house would try. Only ports that
mean "someone can take over this device" are checked, so normal file sharing and web admin pages don't alert.
"""
import socket
from concurrent.futures import ThreadPoolExecutor

PORTS = {
    22: "SSH", 23: "Telnet", 3389: "Remote Desktop", 5900: "VNC", 5901: "VNC", 5938: "TeamViewer",
    7070: "AnyDesk", 5985: "PowerShell remoting", 5986: "PowerShell remoting",
}


def is_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(ips: list[str], ports=None, timeout: float = 0.8) -> dict[str, list[int]]:
    """{ip: [open ports]} for every ip; ips with nothing open map to []."""
    ports = list(ports or PORTS)
    pairs = [(ip, p) for ip in dict.fromkeys(ips) for p in ports]
    out: dict[str, list[int]] = {ip: [] for ip in dict.fromkeys(ips)}
    with ThreadPoolExecutor(max_workers=48) as pool:
        for (ip, p), up in zip(pairs, pool.map(lambda ip_p: is_open(*ip_p, timeout), pairs)):
            if up:
                out[ip].append(p)
    return out


def describe(ports: list[int]) -> str:
    return ", ".join(f"{PORTS.get(p, 'port')} ({p})" for p in sorted(ports))
