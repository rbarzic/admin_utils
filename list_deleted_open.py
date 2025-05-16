#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import re

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
    p.add_argument(
        "--process", action="store_true", default=False,
        help="Also print detailed info about the process holding each file"
    )
    return p.parse_args()

def sizeof_fmt(num, suffix="B"):
    for unit in ["","K","M","G","T","P","E","Z","Y"]:
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Y{suffix}"

def parse_size(s):
    """
    Convert a human-size string like '100M', '2.5G', or bare bytes '123456'
    into an integer number of bytes.
    """
    s = s.strip().upper()
    m = re.match(r'^([0-9]+(?:\.[0-9]+)?)\s*([KMGTPEZY])?B?$', s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size value: '{s}'")
    number, unit = m.groups()
    number = float(number)
    factors = {
        None:    1,
        "":      1,
        "K": 1024**1,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
        "E": 1024**6,
        "Z": 1024**7,
        "Y": 1024**8,
    }
    return int(number * factors[unit])

def run_lsof(path):
    try:
        out = subprocess.check_output(
            ["lsof", "+L1", path],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        # lsof exit code 1 means “no matches” – treat as empty
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
            size_b = int(size_s)
            nlink  = int(nlink_s)
        except ValueError:
            continue
        # keep only truly deleted (nlink==0 & "(deleted)" in name) above min size
        if nlink != 0 or "(deleted)" not in name or size_b < min_bytes:
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

def print_process_info(pid):
    try:
        # pid, ppid, user, elapsed time, %cpu, %mem, full args
        ps_out = subprocess.check_output(
            ["ps", "-p", pid, "-o", "pid,ppid,user,etime,pcpu,pmem,args"],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        ).splitlines()
    except subprocess.CalledProcessError:
        print(f"    (no process info available for PID {pid})")
        return

    # Print each line indented
    for line in ps_out:
        print(f"    {line}")

def main():
    if os.geteuid() != 0:
        print("Warning: not running as root; lsof may not list all files.", file=sys.stderr)

    args = parse_args()
    try:
        min_bytes = parse_size(args.minsize)
    except argparse.ArgumentTypeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    lines   = run_lsof(args.path)
    entries = parse_lsof(lines, min_bytes)

    if not entries:
        print(f"No deleted-but-open files ≥ {args.minsize} found under '{args.path}'.", file=sys.stderr)
        sys.exit(0)

    # sort largest first
    entries.sort(key=lambda e: e["size_b"], reverse=True)

    # print header
    hdr = ["SIZE", "COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "NLINK", "NODE", "NAME"]
    print("\t".join(hdr))

    # print rows
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
        if args.process:
            print_process_info(e["pid"])

if __name__ == "__main__":
    main()




