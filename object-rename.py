#!/usr/bin/env python3
import argparse
import ipaddress
import re
import sys
import glob
import os
from datetime import datetime
from collections import OrderedDict

# ======= CLASSIFICATION RULES =======
RANGES_INT = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
]
RANGES_DMZ = [
    ipaddress.ip_network("172.0.0.0/8"),
]

HOST_PREFIX  = {"INT": "obj-int-host-", "DMZ": "obj-dmz-host-", "EXT": "obj-ext-host-"}
NET_PREFIX   = {"INT": "obj-int-net-",  "DMZ": "obj-dmz-net-",  "EXT": "obj-ext-net-"}
RANGE_INT_PREFIX = "obj-int-range-"
RANGE_EXT_PREFIX = "obj-ext-range-"

# ======= REGEXES =======
OBJ_DECL_RE = re.compile(r'^\s*object\s+network\s+(.+?)\s*$', re.IGNORECASE)
INDENTED_RE = re.compile(r'^\s+(.+?)\s*$')
HOST_RE     = re.compile(r'^\s*host\s+(\S+)\s*$', re.IGNORECASE)
SUBNET_RE   = re.compile(r'^\s*subnet\s+(\S+)\s+(\S+)\s*$', re.IGNORECASE)
RANGE_RE    = re.compile(r'^\s*range\s+(\S+)\s+(\S+)\s*$', re.IGNORECASE)

# ---- NORMALISATION ----
REMOVE_NETWORK_RE  = re.compile(r'network_', re.IGNORECASE)
DUP_HOST_RE        = re.compile(r'^(obj-[^-]+-host-)host', re.IGNORECASE)
TRAILING_DIGITS_RE = re.compile(r'^(.*?)(\d+)$')
DOTS_RE            = re.compile(r'\.+')


def normalize_new_name(name: str) -> str:
    name = REMOVE_NETWORK_RE.sub('', name)
    name = DOTS_RE.sub('.', name).replace('.', '_')
    name = re.sub(r'_+', '_', name)
    name = DUP_HOST_RE.sub(r'\1', name)

    m = TRAILING_DIGITS_RE.match(name)
    if m:
        prefix, digits = m.groups()
        if not prefix.endswith('_'):
            name = f"{prefix}_{digits}"

    return name.strip('_').lower()


def strip_quotes(name: str) -> str:
    name = name.strip()
    if len(name) >= 2 and name[0] == name[-1] and name[0] in "\"'":
        return name[1:-1]
    return name


def classify_ip(ip):
    for n in RANGES_INT:
        if ip in n:
            return "INT"
    for n in RANGES_DMZ:
        if ip in n:
            return "DMZ"
    return "EXT"


def mask_to_prefix(mask):
    if mask.startswith("/"):
        return int(mask[1:])
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def parse_object_blocks(lines):
    i = 0
    while i < len(lines):
        m = OBJ_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue

        name = strip_quotes(m.group(1))
        j = i + 1
        block = []

        while j < len(lines) and INDENTED_RE.match(lines[j]):
            block.append(lines[j])
            j += 1

        yield name, i, j, block
        i = j


def build_mapping_from_blocks(lines, logger):
    mapping = OrderedDict()
    skipped = 0

    for name, _, _, block in parse_object_blocks(lines):

        # 🔒 HARD RULE: ignore any obj-* object
        if name.lower().startswith("obj-"):
            skipped += 1
            logger(f"  SKIP: '{name}' already managed (obj-*)")
            continue

        new_name = None

        for b in block:
            if m := HOST_RE.match(b):
                ip = ipaddress.IPv4Address(m.group(1))
                new_name = HOST_PREFIX[classify_ip(ip)] + name
                break

            if m := SUBNET_RE.match(b):
                net_ip = ipaddress.IPv4Address(m.group(1))
                prefix = mask_to_prefix(m.group(2))
                net = ipaddress.IPv4Network(f"{net_ip}/{prefix}", strict=False)
                new_name = NET_PREFIX[classify_ip(net.network_address)] + name
                break

            if m := RANGE_RE.match(b):
                ip1 = ipaddress.IPv4Address(m.group(1))
                ip2 = ipaddress.IPv4Address(m.group(2))
                scope = classify_ip(ip1)
                new_name = (RANGE_INT_PREFIX if scope != "EXT" else RANGE_EXT_PREFIX) + name
                break

        if new_name:
            clean = normalize_new_name(new_name)
            if clean != name:
                mapping[name] = clean

    return mapping, skipped


def compile_replace_rx(names):
    if not names:
        return re.compile(r'(?!x)x')
    escaped = sorted(map(re.escape, names), key=len, reverse=True)
    return re.compile(r'(?<!\S)(' + "|".join(escaped) + r')(?![^\s,;])')


def apply_mapping(text, mapping):
    rx = compile_replace_rx(mapping.keys())
    return rx.sub(lambda m: mapping[m.group(1)], text)


def log(logf, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    logf.write(line + "\n")


def process_file(path, out_dir, dry_run):
    base = os.path.basename(path)
    root, _ = os.path.splitext(base)

    out_cfg = f"{out_dir}/{root}_RENAMED.asa"
    out_log = f"{out_dir}/chgs-{base}.log"

    with open(path, encoding="utf-8", errors="ignore") as f:
        text = f.read()

    with open(out_log, "w", encoding="utf-8") as logf:
        def logger(m): log(logf, m)

        logger(f"Processing {base}")
        mapping, skipped = build_mapping_from_blocks(text.splitlines(), logger)

        logger(f"Skipped {skipped} existing obj-* objects")
        logger(f"Renaming {len(mapping)} objects")

        for k, v in mapping.items():
            logger(f"  MAP: {k} -> {v}")

        if dry_run:
            logger("Dry-run enabled, no config written")
            return len(mapping)

        updated = apply_mapping(text, mapping)
        with open(out_cfg, "w", encoding="utf-8") as f:
            f.write(updated)

        logger(f"Wrote {out_cfg}")

    return len(mapping)


def main():
    p = argparse.ArgumentParser(description="Rename Cisco ASA object network entries")
    p.add_argument("--glob", default="*.asa")
    p.add_argument("--out", default="out")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(args.glob))
    if not files:
        sys.exit(f"No files matched {args.glob}")

    total = 0
    for f in files:
        total += process_file(f, args.out, args.dry_run)

    print(f"\nDone. Total objects renamed: {total}")


if __name__ == "__main__":
    main()
