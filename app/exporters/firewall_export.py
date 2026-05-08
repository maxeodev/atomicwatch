#!/usr/bin/env python3
"""Sidecar: exports firewall DROP entries from journald to /shared/firewall-drops.jsonl.

Dumps kernel messages containing the ATOMICWATCH-DROP iptables prefix.
Runs every INTERVAL seconds with atomic rename.
"""
import os, subprocess, sys, time

OUTPUT   = os.environ.get("FW_EXPORT_FILE", "/shared/firewall-drops.jsonl")
INTERVAL = int(os.environ.get("FW_EXPORT_INTERVAL", "30"))
SINCE    = os.environ.get("FW_EXPORT_SINCE", "30 days ago")
JDIR     = os.environ.get("JOURNAL_DIR", "/var/log/journal")
PREFIX   = "ATOMICWATCH-DROP"


def dump():
    tmp = OUTPUT + ".tmp"
    # journalctl -k : kernel messages only; --grep filters by MESSAGE field
    cmd = ["journalctl",
           f"--directory={JDIR}",
           "-k",
           f"--grep={PREFIX}",
           "--output=json",
           "--since", SINCE]

    with open(tmp, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)

    if r.returncode != 0:
        print(f"[fw-export] journalctl returned {r.returncode}: "
              f"{r.stderr.decode(errors='replace').strip()}", flush=True, file=sys.stderr)
        os.unlink(tmp)
        return

    os.replace(tmp, OUTPUT)
    size = os.path.getsize(OUTPUT)
    print(f"[fw-export] exported {size:,} bytes → {OUTPUT}", flush=True)


if __name__ == "__main__":
    print(f"[fw-export] starting (interval={INTERVAL}s, since='{SINCE}')", flush=True)
    while True:
        try:
            dump()
        except Exception as e:
            print(f"[fw-export] error: {e}", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)
