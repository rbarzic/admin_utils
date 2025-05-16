

#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os

def parse_args():
    p = argparse.ArgumentParser(
        description="List deleted-but-open files under a path, sorted by size"
    )
    p.add_argument(
        "path", nargs="?", default=".",
        help="Directory or mount point to scan (default: current directory)"
    )
    p.add_argument(
        "--minsize", default="500G",
        help="Minimum file size to report (e.g. 100M, 2T). Default: 500G"
    )
    return p.parse_args()

def sizeof_fmt(num, suffix="B"):
    for unit in ["","K","M","G","T","P","E","Z","Y"]:
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Y{suffix}"

def parse_size(s):
    """Convert a human-size (e.g. '100M') or bare bytes to an int."""
    units = {"":1, "K":1024, "M":1024**2, "G":1024**3, "T":1024**4}
    s = s.strip().upper()
    for suffix, factor in units.items():
        if s.endswith(suffix) and (suffix or s[:-1].isdigit()):
            num = float(s[:-len(suffix)] if suffix else s)
            return int(num * factor)
    raise ValueError(f"Invalid size: {s}")

def run_lsof(path):
    try:
        out = subprocess.check_output(
            ["lsof", "+L1", path],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        out = e.output or ""
    return out.splitlines()

def parse_lsof(lines, min_bytes):
    entries = []
    if len(lines) < 2:
        return entries
    for line in lines[1:]:
        parts = line.split(None, 9)
        if len(parts) < 10:
            continue
        cmd, pid, user, fd, ftype, dev, size_s, nlink_s, node, name = parts
        try:
            size_b  = int(size_s)
            nlink   = int(nlink_s)
        except ValueError:
            continue
        # only keep truly deleted (zero links) and large enough
        if nlink != 0 or "(deleted)" not in name:
            continue
        if size_b < min_bytes:
            continue
        entries.append({
            "size_b":   size_b,
            "command":  cmd,
            "pid":      pid,
            "user":     user,
            "fd":       fd,
            "type":     ftype,
            "device":   dev,
            "nlink":    nlink,
            "node":     node,
            "name":     name,
        })
    return entries

def main():
    if os.geteuid() != 0:
        print("Warning: not running as root; lsof may not list all files.", file=sys.stderr)

    args   = parse_args()
    min_b  = parse_size(args.minsize)
    lines  = run_lsof(args.path)
    entries = parse_lsof(lines, min_b)

    if not entries:
        print(f"No deleted-but-open files ≥ {args.minsize} found under '{args.path}'.", file=sys.stderr)
        sys.exit(0)

    entries.sort(key=lambda e: e["size_b"], reverse=True)

    hdr = ["SIZE", "COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "NLINK", "NODE", "NAME"]
    print("\t".join(hdr))
    for e in entries:
        print("\t".join([
            sizeof_fmt(e["size_b"]),
            e["command"],
            e["pid"],
            e["user"],
            e["fd"],
            e["type"],
            e["device"],
            str(e["nlink"]),
            e["node"],
            e["name"],
        ]))

if __name__ == "__main__":
    main()
