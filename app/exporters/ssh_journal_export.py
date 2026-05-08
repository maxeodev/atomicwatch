#!/usr/bin/env python3
"""Sidecar: exports SSH journal entries from journald to /shared/ssh-journal.jsonl.

Runs a full dump of the last 7 days every INTERVAL seconds (atomic rename,
never leaves an empty window). The main container reads this file via
parse_ssh_journal_file() which already handles the journald JSON format.
"""
import os, subprocess, sys, time

OUTPUT   = os.environ.get("SSH_EXPORT_FILE", "/shared/ssh-journal.jsonl")
INTERVAL = int(os.environ.get("SSH_EXPORT_INTERVAL", "120"))
SINCE    = os.environ.get("SSH_EXPORT_SINCE", "7 days ago")
JDIR     = os.environ.get("JOURNAL_DIR", "/var/log/journal")

UNITS = ["-u", "ssh", "-u", "sshd", "-u", "dropbear"]


def dump():
    tmp = OUTPUT + ".tmp"
    cmd = ["journalctl",
           f"--directory={JDIR}",
           "--output=json",
           "--since", SINCE] + UNITS

    with open(tmp, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)

    if r.returncode != 0:
        # Log warning but keep any previous file intact
        print(f"[ssh-export] journalctl returned {r.returncode}: "
              f"{r.stderr.decode(errors='replace').strip()}", flush=True, file=sys.stderr)
        os.unlink(tmp)
        return

    os.replace(tmp, OUTPUT)
    size = os.path.getsize(OUTPUT)
    print(f"[ssh-export] exported {size:,} bytes → {OUTPUT}", flush=True)


if __name__ == "__main__":
    print(f"[ssh-export] starting (interval={INTERVAL}s, since='{SINCE}')", flush=True)
    while True:
        try:
            dump()
        except Exception as e:
            print(f"[ssh-export] error: {e}", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)
