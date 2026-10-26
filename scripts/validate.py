#!/usr/bin/env python3
"""Validate a z0-hosts repository (the template or a private instance).

Checks, stdlib only (Python 3.11+):
  1. Every hosts/<host_id>/<component>.toml parses and matches schema/host.schema.json.
  2. No file anywhere in the tree holds a tailnet address, a tailnet (MagicDNS) name or a
     secret-shaped value. A private instance holds paths, ports, host ids and serials only.
  3. No TOML key at any depth is named like an address (ip, addr, tailnet, dns_name, ...).
  4. Optional --denylist FILE: one literal per line (blank lines and # comments skipped).
     Any file that contains a literal fails. Use this to prove that a public tree holds
     none of your private values.

Exit 0 when clean, 1 when a check fails, 2 on usage errors.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
HOST_SUBDIRS = {"system", "systemd", "evidence"}  # whole files, scanned but not schema-checked

# 100.64.0.0/10 (Tailscale CGNAT range). 100.64.0.x stays allowed as documentation fixtures.
TAILNET_V4 = re.compile(r"(?<![\d.])100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(\d{1,3})\.(\d{1,3})(?![\d])")
PATTERNS = {
    "tailnet IPv6 address": re.compile(r"(?i)\bfd7a:115c:a1e0:"),
    "tailnet DNS name": re.compile(r"(?i)\b[a-z0-9][a-z0-9-]*\.ts\.net\b"),
    "tailnet id": re.compile(r"(?i)\btail[0-9a-f]{4,}\b"),
    "Tailscale auth key": re.compile(r"\btskey-[A-Za-z0-9-]{10,}"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9]{32,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "inline secret assignment": re.compile(
        r"(?i)\b(password|passwd|secret|token|api_key|apikey)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']"),
}
ADDRESS_KEY = re.compile(
    r"(?i)(^|_)(ip|ip4|ip6|ipv4|ipv6|addr|address|cidr|tailnet|tailscale_ip|magicdns|dns_name|fqdn)(_|$)")


def tailnet_v4_hits(text):
    for m in TAILNET_V4.finditer(text):
        if m.group(1) == "64" and m.group(2) == "0":
            continue
        yield m.group(0)


def scan_text(text, denylist=()):
    """Return a list of (kind, sample) leaks found in text."""
    hits = [("tailnet IPv4 address", h) for h in tailnet_v4_hits(text)]
    for kind, rx in PATTERNS.items():
        hits += [(kind, m.group(0)) for m in rx.finditer(text)]
    hits += [("denylisted literal", lit) for lit in denylist if lit in text]
    return hits


# --- minimal JSON Schema subset (type, properties, additionalProperties, propertyNames,
#     required, items, enum, pattern, minimum, maximum, maxLength, $ref) ---------------
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool}


def check(schema, value, root, where, errors):
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/$defs/"), ref
        schema = {**root["$defs"][ref.split("/")[-1]], **{k: v for k, v in schema.items() if k != "$ref"}}
    t = schema.get("type")
    if t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return errors.append(f"{where}: expected integer, got {type(value).__name__}")
    elif t and not isinstance(value, TYPES[t]):
        return errors.append(f"{where}: expected {t}, got {type(value).__name__}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: {value!r} not in {schema['enum']}")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{where}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{where}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{where}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{where}: above {schema['maximum']}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            check(schema["items"], item, root, f"{where}[{i}]", errors)
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{where}: missing required key {key!r}")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, sub in value.items():
            if "propertyNames" in schema:
                check(schema["propertyNames"], key, root, f"{where}.<key {key!r}>", errors)
            if key in props:
                check(props[key], sub, root, f"{where}.{key}", errors)
            elif extra is False:
                errors.append(f"{where}: unknown key {key!r}")
            elif isinstance(extra, dict):
                check(extra, sub, root, f"{where}.{key}", errors)


def address_keys(value, where):
    if isinstance(value, dict):
        for key, sub in value.items():
            if ADDRESS_KEY.search(key):
                yield f"{where}.{key}"
            yield from address_keys(sub, f"{where}.{key}")
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            yield from address_keys(sub, f"{where}[{i}]")


def load_host(host_dir, components):
    """Return ({component: data}, errors) for one hosts/<id>/ directory."""
    data, errors = {}, []
    for entry in sorted(host_dir.iterdir()):
        if entry.is_dir():
            if entry.name not in HOST_SUBDIRS:
                errors.append(f"{entry}: unexpected directory (allowed: {sorted(HOST_SUBDIRS)})")
            continue
        if entry.name.startswith("."):
            continue
        if entry.suffix != ".toml":
            errors.append(f"{entry}: only <component>.toml files belong in a host directory")
            continue
        if entry.stem not in components:
            errors.append(f"{entry}: unknown component {entry.stem!r} (known: {sorted(components)})")
            continue
        try:
            data[entry.stem] = tomllib.loads(entry.read_text())
        except tomllib.TOMLDecodeError as exc:
            errors.append(f"{entry}: TOML error: {exc}")
    return data, errors


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def validate(root, denylist=()):
    root = Path(root)
    schema = json.loads((Path(__file__).resolve().parents[1] / "schema" / "host.schema.json").read_text())
    local_schema = root / "schema" / "host.schema.json"
    if local_schema.is_file():
        schema = json.loads(local_schema.read_text())
    components = set(schema["properties"])
    errors, hosts = [], []
    hosts_dir = root / "hosts"
    for host_dir in sorted(p for p in hosts_dir.iterdir() if p.is_dir()) if hosts_dir.is_dir() else []:
        hosts.append(host_dir.name)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", host_dir.name):
            errors.append(f"{host_dir}: host_id must match [a-z0-9][a-z0-9_-]*")
        data, errs = load_host(host_dir, components)
        errors += errs
        check(schema, data, schema, f"hosts/{host_dir.name}", errors)
        errors += [f"{k}: address-shaped key is never allowed" for k in address_keys(data, f"hosts/{host_dir.name}")]
    for path in iter_files(root):
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root)
        for kind, sample in scan_text(text, denylist):
            # Never echo a denylisted literal or a secret: name the file and the kind only.
            shown = "" if kind in ("denylisted literal",) or "key" in kind or "token" in kind \
                or "secret" in kind else f" ({sample})"
            errors.append(f"{rel}: {kind}{shown}")
    return hosts, errors


def read_denylist(path):
    lines = Path(path).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?", default=str(ROOT), help="repository root (default: this repo)")
    ap.add_argument("--denylist", help="file of private literals that must not appear")
    args = ap.parse_args(argv)
    if not Path(args.root).is_dir():
        print(f"validate: {args.root} is not a directory", file=sys.stderr)
        return 2
    denylist = read_denylist(args.denylist) if args.denylist else []
    hosts, errors = validate(args.root, denylist)
    for err in errors:
        print(f"FAIL {err}")
    print(f"validate: {len(hosts)} host dir(s) [{', '.join(hosts)}], "
          f"{len(denylist)} denylist literal(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
