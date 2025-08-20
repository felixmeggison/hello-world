#!/usr/bin/env python3
import argparse
import csv
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
from pathlib import Path

def parse_args():
    p = argparse.ArgumentParser(
        description="Scan hosts for open ports in a range and flag likely FIX servers."
    )
    p.add_argument("-i", "--input", required=True, help="Path to host list file (one host/IP per line)")
    p.add_argument("-o", "--output", required=True, help="Output CSV path")
    p.add_argument("--min-ports", type=int, default=5, help="Threshold to flag as FIX server (default: 5)")
    p.add_argument("--ports", default="10000-12000", help="Port range to scan (default: 10000-12000)")
    p.add_argument("--extra-nmap-args", default="-T4 -n --open -Pn",
                   help='Extra nmap args (default: "-T4 -n --open -Pn")')
    return p.parse_args()

def ensure_nmap():
    if shutil.which("nmap") is None:
        sys.exit("ERROR: nmap not found in PATH. Install nmap and try again.")

def read_hosts(path):
    hosts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    if not hosts:
        sys.exit("ERROR: No hosts found in input.")
    return hosts

def run_nmap(host_file, port_range, extra_args):
    # Build command: nmap -iL host_file -p <range> <extra_args> -oX -
    # Use a temporary file for -iL to avoid shell quoting issues if user passed a path with spaces.
    cmd = ["nmap", "-iL", host_file, "-p", port_range] + extra_args.split() + ["-oX", "-"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except Exception as e:
        sys.exit(f"ERROR: Failed to run nmap: {e}")
    if res.returncode not in (0, 1):  # 0 OK, 1 some closed/filtered hosts—still usable
        sys.stderr.write(res.stderr)
        sys.exit(f"ERROR: nmap exited with code {res.returncode}. See stderr above.")
    return res.stdout

def parse_nmap_xml(xml_text):
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        sys.exit(f"ERROR: Failed parsing nmap XML: {e}")

    for h in root.findall("host"):
        # address
        addr = None
        for a in h.findall("address"):
            addr = a.attrib.get("addr")
            # prefer IPv4 if multiple
            if a.attrib.get("addrtype") == "ipv4":
                addr = a.attrib.get("addr")
                break

        # hostname (optional)
        hostname = ""
        hostnames = h.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name", "")

        # open ports
        open_ports = []
        ports_node = h.find("ports")
        if ports_node is not None:
            for p in ports_node.findall("port"):
                state = p.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    try:
                        open_ports.append(int(p.attrib.get("portid", "-1")))
                    except ValueError:
                        pass

        # Skip hosts with no address (rare)
        if not addr:
            continue

        results.append({
            "host": addr,
            "hostname": hostname,
            "open_ports": sorted(open_ports),
            "open_count": len(open_ports),
        })
    return results

def write_csv(rows, output_path, min_ports):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "hostname", "is_fix_server", "open_port_count", "open_ports"])
        for r in rows:
            is_fix = "yes" if r["open_count"] >= min_ports else "no"
            w.writerow([
                r["host"],
                r["hostname"],
                is_fix,
                r["open_count"],
                " ".join(map(str, r["open_ports"])) if r["open_ports"] else ""
            ])

def main():
    args = parse_args()
    ensure_nmap()
    hosts = read_hosts(args.input)

    # Write hosts to a clean temp file for -iL
    with NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
        for h in hosts:
            tf.write(h + "\n")
        tmp_hosts_file = tf.name

    try:
        xml_out = run_nmap(tmp_hosts_file, args.ports, args.extra_nmap_args)
    finally:
        # Best-effort cleanup
        try:
            Path(tmp_hosts_file).unlink(missing_ok=True)
        except Exception:
            pass

    parsed = parse_nmap_xml(xml_out)
    write_csv(parsed, args.output, args.min_ports)

    # Quick summary to stdout
    total = len(parsed)
    fixes = sum(1 for r in parsed if r["open_count"] >= args.min_ports)
    print(f"Scanned {total} host(s). Likely FIX servers (≥{args.min_ports} ports in {args.ports}): {fixes}")
    print(f"CSV written to: {args.output}")

if __name__ == "__main__":
    main()
