#!/usr/bin/env python3
"""
Per-host nmap scanner for ports 10000–12000 that:
- Scans ONE host at a time (resilient to interruptions)
- Saves full nmap output for each host in all formats (-oA)
- Builds a CSV summary with host, fix flag (>= min ports), and open port count/list
"""

import argparse
import csv
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="Scan hosts (one-per-line) for a port range and flag likely FIX servers (per-host, incremental CSV)."
    )
    p.add_argument("-i", "--input", required=True, help="Path to host list file (one host/IP per line)")
    p.add_argument("-o", "--output", required=True, help="Output CSV path")
    p.add_argument("--outdir", default="nmap_scans", help="Directory to save raw nmap outputs (default: nmap_scans)")
    p.add_argument("--min-ports", type=int, default=5, help="Threshold to flag as FIX server (default: 5)")
    p.add_argument("--ports", default="10000-12000", help="Port range to scan (default: 10000-12000)")
    p.add_argument(
        "--extra-nmap-args",
        default="-T4 -n --open -Pn",
        help='Extra nmap args (default: "-T4 -n --open -Pn")',
    )
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


def sanitize_basename(s: str) -> str:
    # Safe for filenames: replace characters that can appear in IPv6/paths/etc.
    return s.replace("/", "_").replace("\\", "_").replace(":", "_").replace("*", "_").replace("?", "_").replace("|", "_")


def run_nmap_single(host, port_range, extra_args, outdir):
    """
    Runs nmap for a single host, writes -oA files to outdir/<host_sanitized>.*
    Returns the XML text (read back from the generated .xml) for parsing.
    """
    Path(outdir).mkdir(parents=True, exist_ok=True)
    outfile_base = Path(outdir) / sanitize_basename(host)
    cmd = ["nmap", "-p", port_range] + extra_args.split() + ["-oA", str(outfile_base), host]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except Exception as e:
        print(f"ERROR: Failed to run nmap for {host}: {e}", file=sys.stderr)
        return ""

    if res.returncode not in (0, 1):  # 0 OK; 1 means some issues but output usually usable
        sys.stderr.write(res.stderr)
        print(f"WARNING: nmap exited with code {res.returncode} for host {host}. Continuing.", file=sys.stderr)

    xml_path = f"{outfile_base}.xml"
    try:
        return Path(xml_path).read_text(encoding="utf-8")
    except Exception as e:
        print(f"WARNING: Could not read XML output for {host}: {e}", file=sys.stderr)
        return ""


def parse_nmap_xml(xml_text):
    """
    Parses nmap XML (possibly single-host) and returns a list of rows:
    { host, hostname, open_ports [ints], open_count }
    """
    results = []
    if not xml_text:
        return results
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"WARNING: Failed to parse nmap XML: {e}", file=sys.stderr)
        return results

    for h in root.findall("host"):
        # address: prefer ipv4 if present
        addr = None
        for a in h.findall("address"):
            addr = a.attrib.get("addr")
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
                    except (ValueError, TypeError):
                        pass

        if addr:
            results.append(
                {
                    "host": addr,
                    "hostname": hostname,
                    "open_ports": sorted(open_ports),
                    "open_count": len(open_ports),
                }
            )
    return results


def main():
    args = parse_args()
    ensure_nmap()
    hosts = read_hosts(args.input)

    # init CSV header (overwrite each run)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "hostname", "is_fix_server", "open_port_count", "open_ports"])

    total = 0
    fixes = 0

    for host in hosts:
        print(f"[+] Scanning {host} ...")
        xml_out = run_nmap_single(host, args.ports, args.extra_nmap_args, args.outdir)
        parsed_rows = parse_nmap_xml(xml_out)

        # Try to match exact host; fallback to first parsed row if nmap rewrote address
        row = next((r for r in parsed_rows if r["host"] == host), None)
        if not row and parsed_rows:
            row = parsed_rows[0]
        if not row:
            row = {"host": host, "hostname": "", "open_ports": [], "open_count": 0}

        is_fix = "yes" if row["open_count"] >= args.min_ports else "no"

        # Append immediately for resilience
        with open(args.output, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                [
                    row["host"],
                    row.get("hostname", ""),
                    is_fix,
                    row["open_count"],
                    " ".join(map(str, row["open_ports"])) if row["open_ports"] else "",
                ]
            )

        total += 1
        fixes += (is_fix == "yes")

    print(f"Scanned {total} host(s). Likely FIX servers (≥{args.min_ports} ports in {args.ports}): {fixes}")
    print(f"CSV written to: {args.output}")
    print(f"Raw nmap outputs per host are in: {args.outdir} ( .nmap / .gnmap / .xml )")


if __name__ == "__main__":
    main()
