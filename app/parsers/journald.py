import json
import os
import re
from collections import defaultdict, deque
from datetime import datetime

RE_INVALID_USER = re.compile(r'Invalid user (\S+) from ([\d\.]+)')
RE_FAILED_PASS = re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d\.]+)')
RE_MAX_AUTH = re.compile(r'maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d\.]+)')
RE_CONN_RESET = re.compile(r'Connection reset by (?:authenticating user |invalid user )?(\S+) ([\d\.]+)')
RE_TIMEOUT = re.compile(r'Connection from ([\d\.]+) port \d+ on .* timed out')


async def parse_journald_ssh(journal_dir: str, machine_id_path: str = "", days: int = 7) -> dict:
    ssh_jsonl = os.environ.get("SSH_JOURNAL_FILE", "/host/ssh-journal.jsonl")
    return parse_ssh_journal_file(ssh_jsonl)


def parse_ssh_journal_file(jsonl_path: str) -> dict:
    data: dict[str, dict] = defaultdict(lambda: {
        "tried_users": set(),
        "attempts": 0,
        "events": deque(maxlen=100),
        "first_seen": None,
        "last_seen": None,
    })

    if not os.path.exists(jsonl_path):
        return {}

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
            if isinstance(msg, list):
                msg = "".join(chr(b) if isinstance(b, int) else b for b in msg)
            if not isinstance(msg, str):
                continue

            ip = None
            user = None

            m = RE_INVALID_USER.search(msg)
            if m:
                user, ip = m.group(1), m.group(2)

            if not ip:
                m = RE_FAILED_PASS.search(msg)
                if m:
                    user, ip = m.group(1), m.group(2)

            if not ip:
                m = RE_MAX_AUTH.search(msg)
                if m:
                    user, ip = m.group(1), m.group(2)

            if not ip:
                m = RE_CONN_RESET.search(msg)
                if m:
                    user, ip = m.group(1), m.group(2)

            if not ip:
                m = RE_TIMEOUT.search(msg)
                if m:
                    ip = m.group(1)

            if ip:
                ts_us = entry.get("__REALTIME_TIMESTAMP", "")
                ts_dt = None
                ts_iso = None
                if ts_us:
                    try:
                        ts_dt = datetime.utcfromtimestamp(int(ts_us) / 1_000_000)
                        ts_iso = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError):
                        pass

                entry_data = data[ip]
                entry_data["attempts"] += 1
                if user and user != "nobody":
                    entry_data["tried_users"].add(user)

                if ts_dt:
                    if entry_data["first_seen"] is None or ts_dt < entry_data["first_seen"]:
                        entry_data["first_seen"] = ts_dt
                    if entry_data["last_seen"] is None or ts_dt > entry_data["last_seen"]:
                        entry_data["last_seen"] = ts_dt

                entry_data["events"].append({
                    "ts": ts_iso,
                    "msg": msg[:200],
                    "user": user,
                })

    return {
        ip: {
            **d,
            "events": list(d["events"]),
            "tried_users": d["tried_users"],
        }
        for ip, d in data.items()
    }


def classify_attack(tried_users: set, attempts: int) -> str:
    if not tried_users:
        return "SSH Probe"
    if tried_users == {"root"}:
        return "SSH Root Bruteforce"
    if len(tried_users) > 5:
        return "SSH Dictionary Attack"
    if len(tried_users) > 1:
        return "SSH User Enumeration"
    return "SSH Bruteforce"
