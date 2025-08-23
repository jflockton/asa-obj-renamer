#!/usr/bin/env python3
import argparse
import ipaddress
import re
import sys
import glob
import os
from datetime import datetime
from collections import OrderedDict

# ======= CLASSIFICATION RULES (tweak as needed) =======
RANGES_INT = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
]
# Treat ALL 172/8 as DMZ (per your rule). Everything else is EXT.
RANGES_DMZ = [
    ipaddress.ip_network("172.0.0.0/8"),
]

HOST_PREFIX  = {"INT": "obj-int-host-", "DMZ": "obj-dmz-host-", "EXT": "obj-ext-host-"}
NET_PREFIX   = {"INT": "obj-int-net-",  "DMZ": "obj-dmz-net-",  "EXT": "obj-ext-net-"}
# Ranges: INT vs EXT only (DMZ counts as internal-like)
RANGE_INT_PREFIX = "obj-int-range-"
RANGE_EXT_PREFIX = "obj-ext-range-"

# ======= REGEXES =======
OBJ_DECL_RE = re.compile(r'^\s*object\s+network\s+(.+?)\s*$', flags=re.IGNORECASE)
INDENTED_RE = re.compile(r'^\s+(.+?)\s*$')
HOST_RE     = re.compile(r'^\s*host\s+(\S+)\s*$', flags=re.IGNORECASE)
SUBNET_RE   = re.compile(r'^\s*subnet\s+(\S+)\s+(\S+)\s*$', flags=re.IGNORECASE)
RANGE_RE    = re.compile(r'^\s*range\s+(\S+)\s+(\S+)\s*$', flags=re.IGNORECASE)

# Already-prefixed object name? (skip adding a new prefix if this matches)
ALREADY_PREFIXED_RE = re.compile(r'^obj-(?:int|dmz|ext)-(?:host|net|range)-', re.IGNORECASE)

# ---- NORMALIZE NEW OBJECT NAMES (robust) ----
REMOVE_NETWORK_RE  = re.compile(r'network_', re.IGNORECASE)
DUP_HOST_RE        = re.compile(r'^(obj-[^-]+-host-)host', re.IGNORECASE)
TRAILING_DIGITS_RE = re.compile(r'^(.*?)(\d+)$')  # prefix + WHOLE trailing digit block
DOTS_RE            = re.compile(r'\.+')           # collapse runs of dots before swapping

def normalize_new_name(name: str) -> str:
    """
    Clean the computed new object name:
      - remove 'network_' (case-insensitive)
      - replace '.' with '_' (after collapsing '...') and collapse multiple '_'
      - remove duplicate 'host' after the prefix (obj-*-host-hostX -> obj-*-host-X)
      - add ONE underscore before the WHOLE trailing digits block (preserve leading zeros),
        but do nothing if the prefix already ends with '_'
      - trim leading/trailing '_' and lowercase everything
    """
    # 1) drop 'network_'
    name = REMOVE_NETWORK_RE.sub('', name)
    # 2) dots -> underscores (collapse runs of dots first)
    name = DOTS_RE.sub('.', name).replace('.', '_')
    # 3) collapse multiple underscores
    name = re.sub(r'_+', '_', name)
    # 4) remove duplicate 'host' after the prefix
    name = DUP_HOST_RE.sub(r'\1', name)
    # 5) underscore the entire trailing digits block once (preserve 07 as 07)
    m = TRAILING_DIGITS_RE.match(name)
    if m:
        prefix, digits = m.group(1), m.group(2)
        if prefix.endswith('_'):
            name = f"{prefix}{digits}"
        else:
            name = f"{prefix}_{digits}"
    # 6) trim stray underscores and force lowercase
    name = name.strip('_')
    return name.lower()

# -----------------------------------------------------------------------------

def strip_quotes(name: str) -> str:
    name = name.strip()
    if len(name) >= 2 and ((name[0] == name[-1] == '"') or (name[0] == name[-1] == "'")):
        return name[1:-1]
    return name

def mask_to_prefix(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        if mask.startswith("/"):
            return int(mask[1:])
        raise

def classify_ip(ip: ipaddress.IPv4Address) -> str:
    for net in RANGES_INT:
        if ip in net:
            return "INT"
    for net in RANGES_DMZ:
        if ip in net:
            return "DMZ"
    return "EXT"

def classify_network(ipnet: ipaddress.IPv4Network) -> str:
    return classify_ip(ipnet.network_address)

def classify_range(ip1: ipaddress.IPv4Address, ip2: ipaddress.IPv4Address) -> str:
    # DMZ counts as internal-like for range naming
    c1, c2 = classify_ip(ip1), classify_ip(ip2)
    return "INT" if c1 in ("INT", "DMZ") and c2 in ("INT", "DMZ") else "EXT"

def parse_object_blocks(lines):
    """
    Yields: (orig_name, block_start_idx, block_end_idx_exclusive, block_lines)
    block_lines excludes the 'object network' line; continues while lines are indented.
    """
    i = 0
    n = len(lines)
    while i < n:
        m = OBJ_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = strip_quotes(m.group(1))

        j = i + 1
        block = []
        while j < n and INDENTED_RE.match(lines[j]):
            block.append(lines[j])
            j += 1

        yield (name, i, j, block)
        i = j

def build_mapping_from_blocks(lines, logger=None):
    """
    Returns OrderedDict of {old_name: normalized_new_name} preserving discovery order.
    Considers only object network blocks that contain 'host', 'subnet', or 'range'.
    """
    mapping = OrderedDict()
    for name, start, end, block in parse_object_blocks(lines):
        new_name = None

        # If the existing object name is already 'obj-(int|dmz|ext)-(host|net|range)-*',
        # we KEEP its prefix/type and only normalize it.
        if ALREADY_PREFIXED_RE.match(name):
            new_name = name  # no new prefix
        else:
            # Otherwise, infer scope/type and build the prefixed name
            for bline in block:
                mh = HOST_RE.match(bline)
                if mh:
                    try:
                        ip = ipaddress.IPv4Address(mh.group(1))
                        scope = classify_ip(ip)
                        new_name = HOST_PREFIX[scope] + name
                        break
                    except Exception:
                        if logger: logger(f"  WARN: Invalid host IP in '{name}': {mh.group(1)}")
                        continue

                ms = SUBNET_RE.match(bline)
                if ms:
                    try:
                        net_ip = ipaddress.IPv4Address(ms.group(1))
                        prefix = mask_to_prefix(ms.group(2))
                        net = ipaddress.IPv4Network(f"{net_ip}/{prefix}", strict=False)
                        scope = classify_network(net)
                        new_name = NET_PREFIX[scope] + name
                        break
                    except Exception:
                        if logger: logger(f"  WARN: Invalid subnet in '{name}': {ms.group(1)} {ms.group(2)}")
                        continue

                mr = RANGE_RE.match(bline)
                if mr:
                    try:
                        ip1 = ipaddress.IPv4Address(mr.group(1))
                        ip2 = ipaddress.IPv4Address(mr.group(2))
                        scope = classify_range(ip1, ip2)
                        new_name = (RANGE_INT_PREFIX if scope == "INT" else RANGE_EXT_PREFIX) + name
                        break
                    except Exception:
                        if logger: logger(f"  WARN: Invalid range in '{name}': {mr.group(1)} {mr.group(2)}")
                        continue

        if new_name and new_name != name and name not in mapping:
            clean = normalize_new_name(new_name)
            mapping[name] = clean
        elif new_name and new_name == name and name not in mapping:
            # Name already prefixed — still normalize (lowercase, underscores, etc.)
            clean = normalize_new_name(new_name)
            if clean != name:  # only map if it changes after normalization
                mapping[name] = clean

    return mapping

def compile_global_replace_regex(names):
    """
    Safe token replacement: match exact names, not substrings.
    Preceded by start/whitespace; followed by end/whitespace/comma/semicolon.
    """
    if not names:
        return re.compile(r'(?!x)x')
    escaped = sorted((re.escape(n) for n in names), key=len, reverse=True)
    pattern = r'(?<!\S)(' + "|".join(escaped) + r')(?![^\s,;])'
    return re.compile(pattern)

def apply_mapping_to_text(text: str, mapping: dict) -> str:
    if not mapping:
        return text
    rx = compile_global_replace_regex(mapping.keys())
    return rx.sub(lambda m: mapping.get(m.group(1), m.group(1)), text)

def ensure_out_dir(path="out"):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
    return path

def log_both(logf, msg):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line)
    logf.write(line + "\n")
    logf.flush()

def write_obj_list(mapping: OrderedDict, out_path: str):
    # One new (normalized, lowercase) name per line
    with open(out_path, "w", encoding="utf-8") as f:
        for _, new in mapping.items():
            f.write(f"{new}\n")

def process_file(in_path, out_dir, dry_run=False):
    base = os.path.basename(in_path)
    root, _ = os.path.splitext(base)

    out_cfg = os.path.join(out_dir, f"{root}_RENAMED.asa")
    out_log = os.path.join(out_dir, f"chgs-{base}.log")
    out_obj = os.path.join(out_dir, f"obj_{base}.asa.txt")

    with open(in_path, "r", encoding="utf-8", errors="ignore") as f:
        original_text = f.read()
    lines = original_text.splitlines()

    with open(out_log, "w", encoding="utf-8") as logf:
        def logger(m): log_both(logf, m)
        logger(f"Processing: {base}")

        mapping = build_mapping_from_blocks(lines, logger=logger)
        logger(f"Found {len(mapping)} eligible object network names to rename.")

        # collision detection
        reverse, collisions = {}, []
        for old, new in mapping.items():
            if new in reverse and reverse[new] != old:
                collisions.append((new, reverse[new], old))
            else:
                reverse[new] = old

        if collisions:
            logger("WARNING: Name collisions detected (two old names -> same new):")
            for new, first_old, second_old in collisions:
                logger(f"  {first_old} and {second_old} -> {new}")

        # preview mappings
        for old, new in mapping.items():
            logger(f"  MAP: {old} -> {new}")

        if dry_run:
            write_obj_list(mapping, out_obj)  # still write names for review
            logger(f"Wrote: {out_obj}")
            logger("Dry-run enabled; not writing renamed config.")
            return {"file": base, "renamed": len(mapping), "output": None, "log": out_log, "objlist": out_obj}

        # apply + write
        updated_text = apply_mapping_to_text(original_text, mapping)
        with open(out_cfg, "w", encoding="utf-8") as outf:
            outf.write(updated_text)
        write_obj_list(mapping, out_obj)

        logger(f"Wrote: {out_cfg}")
        logger(f"Wrote: {out_obj}")
        logger("Done.")

    return {"file": base, "renamed": len(mapping), "output": out_cfg, "log": out_log, "objlist": out_obj}

def main():
    parser = argparse.ArgumentParser(description="Batch‑rename Cisco ASA 'object network' names and update references.")
    parser.add_argument("--dry-run", action="store_true", help="Analyze and log changes; write obj_ list; no renamed configs.")
    parser.add_argument("--glob", default="*.asa", help="Glob for input files (default: *.asa)")
    parser.add_argument("--out", default="out", help="Output folder (default: out)")
    args = parser.parse_args()

    out_dir = ensure_out_dir(args.out)
    files = sorted(glob.glob(args.glob))
    if not files:
        print(f"No files matched pattern: {args.glob}")
        sys.exit(1)

    totals = 0
    print(f"Discovered {len(files)} file(s) to process.")
    for fp in files:
        res = process_file(fp, out_dir, dry_run=args.dry_run)
        totals += res["renamed"]
    print(f"\nAll done. Total objects renamed across batch: {totals}")

if __name__ == "__main__":
    main()
