import json
import os
import re
from datetime import datetime

RE_SRC       = re.compile(r'SRC=([\d\.]+)')
RE_DPT       = re.compile(r'DPT=(\d+)')
RE_SPT       = re.compile(r'SPT=(\d+)')
RE_PROTO     = re.compile(r'PROTO=(\w+)')
RE_ICMP_TYPE = re.compile(r'TYPE=(\d+)')

ICMP_TYPES = {
    0: "ICMP Reply", 8: "ICMP Ping", 3: "ICMP Unreachable",
    11: "ICMP TTL-Exceeded", 5: "ICMP Redirect",
}

KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7547: "CWMP", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def parse_firewall_drops(jsonl_path: str) -> list[dict]:
    events = []

    if not os.path.exists(jsonl_path):
        return []

    with open(jsonl_path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg = entry.get("MESSAGE", "")
            if not isinstance(msg, str) or "ATOMICWATCH-DROP" not in msg:
                continue

            src_m = RE_SRC.search(msg)
            if not src_m:
                continue

            ip = src_m.group(1)
            dpt_m  = RE_DPT.search(msg)
            spt_m  = RE_SPT.search(msg)
            proto_m = RE_PROTO.search(msg)

            dpt   = int(dpt_m.group(1))  if dpt_m   else None
            spt   = int(spt_m.group(1))  if spt_m   else None
            proto = proto_m.group(1)      if proto_m else "UNKNOWN"

            if proto == "ICMP":
                icmp_m = RE_ICMP_TYPE.search(msg)
                icmp_t = int(icmp_m.group(1)) if icmp_m else 8
                service = ICMP_TYPES.get(icmp_t, f"ICMP-{icmp_t}")
            else:
                service = KNOWN_PORTS.get(dpt, f"PORT-{dpt}" if dpt else "?")

            ts_us = entry.get("__REALTIME_TIMESTAMP", "")
            ts_iso = None
            if ts_us:
                try:
                    ts_iso = datetime.utcfromtimestamp(int(ts_us) / 1_000_000).strftime("%Y-%m-%dT%H:%M:%SZ")
                except (ValueError, OSError):
                    pass

            events.append({
                "ip":      ip,
                "dpt":     dpt,
                "spt":     spt,
                "proto":   proto,
                "service": service,
                "ts":      ts_iso,
            })

    return events
