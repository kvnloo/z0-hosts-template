"""Reference reader for a z0-hosts instance (stdlib only, Python 3.11+).

Consumer repos vendor a copy of this file; they never import it from here at runtime.

    import z0_hosts
    z0_hosts.host_id()            # "desktop", or "default" when no host directory matches
    z0_hosts.overlay("dash")      # dict from hosts/<host_id>/dash.toml, {} when absent
    z0_hosts.self_ip4()           # discovered at runtime, never read from the overlay

Lookup order for host_id: $Z0_HOST_ID; then the hosts/*/host.toml whose match_hostnames
holds the Tailscale Self.HostName; then the one that holds the OS hostname; else "default".
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tomllib
from pathlib import Path

TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")


def hosts_dir() -> Path:
    return Path(os.environ.get("Z0_HOSTS_DIR") or Path.home() / ".config" / "z0-hosts")


def _load(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text())
    except FileNotFoundError:
        return {}


def tailscale_status() -> dict:
    exe = shutil.which("tailscale")
    if not exe:
        return {}
    try:
        out = subprocess.run([exe, "status", "--json"], capture_output=True, text=True, timeout=5, check=True)
        return json.loads(out.stdout)
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        return {}


def host_id(root: Path | None = None, hostname: str | None = None) -> str:
    if os.environ.get("Z0_HOST_ID"):
        return os.environ["Z0_HOST_ID"]
    root = root or hosts_dir()
    candidates = [hostname] if hostname else [
        (tailscale_status().get("Self") or {}).get("HostName"), socket.gethostname()]
    dirs = sorted(p for p in (root / "hosts").glob("*/") if p.is_dir()) if (root / "hosts").is_dir() else []
    for name in filter(None, candidates):
        for d in dirs:
            if name in (_load(d / "host.toml").get("match_hostnames") or []):
                return d.name
    return "default"


def overlay(component: str, root: Path | None = None) -> dict:
    root = root or hosts_dir()
    return _load(root / "hosts" / host_id(root) / f"{component}.toml")


def self_ip4() -> str | None:
    for ip in (tailscale_status().get("Self") or {}).get("TailscaleIPs") or []:
        if ":" not in ip:
            return ip
    return None


def self_dns_name() -> str | None:
    name = (tailscale_status().get("Self") or {}).get("DNSName") or ""
    return name.rstrip(".") or None


def peer_ip4(peer_hostname: str) -> str | None:
    for peer in (tailscale_status().get("Peer") or {}).values():
        if peer.get("HostName") == peer_hostname:
            return next((ip for ip in peer.get("TailscaleIPs") or [] if ":" not in ip), None)
    return None


def in_tailnet_cidr(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in TAILNET_V4
    except ValueError:
        return False
