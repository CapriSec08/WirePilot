from __future__ import annotations

import ipaddress
import platform
import shutil
import socket
import ssl
import time

from .core import Config, run_bounded


def local_snapshot():
    """Fixed read-only commands; diagnostics describe the MCP host, not the user's PC."""
    system = platform.system()
    commands = {
        "Linux": {
            "interfaces": ["ip", "-j", "address"],
            "routes": ["ip", "-j", "route", "show", "table", "all"],
            "neighbors": ["ip", "-j", "neigh"],
            "sockets": ["ss", "-tun"],
        },
        "Windows": {
            "interfaces": ["ipconfig", "/all"],
            "routes": ["route", "print"],
            "neighbors": ["arp", "-a"],
            "sockets": ["netstat", "-ano"],
        },
        "Darwin": {
            "interfaces": ["ifconfig"],
            "routes": ["netstat", "-rn"],
            "neighbors": ["arp", "-a"],
            "sockets": ["netstat", "-an"],
        },
    }.get(system, {})
    results = {}
    for name, command in commands.items():
        if not shutil.which(command[0]):
            results[name] = {
                "status": "unavailable",
                "reason": command[0] + " not installed",
            }
            continue
        try:
            results[name] = {
                "status": "ok",
                "output": run_bounded(command, timeout=10, max_bytes=1024 * 1024),
            }
        except (ValueError, OSError) as exc:
            results[name] = {"status": "error", "reason": str(exc)}
    return {
        "system": system,
        "vantage_point": "Machine/container running this WirePilot MCP server.",
        "results": results,
    }


def endpoint_probe(config: Config, address: str, port: int, tls_server_name: str = ""):
    """One TCP connection, optionally a verified TLS handshake. No HTTP/payload or scanning."""
    ip = ipaddress.ip_address(address)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be 1–65535.")
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in config.probe_cidrs]
    if not any(ip in network for network in networks):
        raise ValueError(
            "Target is outside WIREPILOT_PROBE_CIDRS. Configure authorised ranges at server startup."
        )
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError("A unicast target address is required.")
    if len(tls_server_name) > 253 or any(c.isspace() for c in tls_server_name):
        raise ValueError("Invalid TLS server name.")
    start = time.monotonic()
    result = {
        "address": str(ip),
        "port": port,
        "vantage_point": "WirePilot server host",
        "tcp": "not_tested",
        "tls": "not_requested",
    }
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((str(ip), port))
            result.update(
                tcp="connected",
                tcp_connect_ms=round((time.monotonic() - start) * 1000, 2),
            )
            if tls_server_name:
                result["tls"] = "handshake_started"
                context = ssl.create_default_context()
                with context.wrap_socket(
                    sock, server_hostname=tls_server_name
                ) as secure:
                    cert = secure.getpeercert()
                    result.update(
                        tls="verified",
                        tls_version=secure.version(),
                        cipher=secure.cipher(),
                        certificate_expires=cert.get("notAfter"),
                        tls_server_name=tls_server_name,
                    )
    except (OSError, ssl.SSLError) as exc:
        if result["tcp"] == "not_tested":
            result["tcp"] = "failed"
        elif tls_server_name:
            result["tls"] = "failed"
        result["error"] = str(exc)
    result["interpretation"] = (
        "A TCP/TLS result does not establish application health; failures do not alone identify the failing device."
    )
    return result
