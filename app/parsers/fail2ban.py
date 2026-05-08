import re
import os
from datetime import datetime
from collections import defaultdict

RE_FOUND = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ '
    r'fail2ban\.filter\s+\[\d+\]: INFO\s+'
    r'\[(\w+)\] Found ([\d\.a-f:]+)'
)
RE_BAN = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ '
    r'fail2ban\.actions\s+\[\d+\]: NOTICE\s+'
    r'\[(\w+)\] (Ban|Unban|Restore Ban) ([\d\.a-f:]+)$'
)


def parse_fail2ban_log(log_path: str) -> dict:
    """
    Returns dict keyed by IP:
    {
      ip: {
        jail, attempts, status, ban_count,
        first_seen, last_seen, banned_at
      }
    }
    """
    data: dict[str, dict] = defaultdict(lambda: {
        "jail": "sshd",
        "attempts": 0,
        "status": "active",
        "ban_count": 0,
        "first_seen": None,
        "last_seen": None,
        "banned_at": None,
    })

    if not os.path.exists(log_path):
        return {}

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()

            m = RE_FOUND.match(line)
            if m:
                ts_str, jail, ip = m.group(1), m.group(2), m.group(3)
                ts = _parse_ts(ts_str)
                entry = data[ip]
                entry["jail"] = jail
                entry["attempts"] += 1
                entry["last_seen"] = ts
                if entry["first_seen"] is None:
                    entry["first_seen"] = ts
                continue

            m = RE_BAN.match(line)
            if m:
                ts_str, jail, action, ip = m.group(1), m.group(2), m.group(3), m.group(4)
                ts = _parse_ts(ts_str)
                entry = data[ip]
                entry["jail"] = jail
                if action in ("Ban", "Restore Ban"):
                    entry["status"] = "banned"
                    entry["ban_count"] += 1
                    entry["banned_at"] = ts
                elif action == "Unban":
                    entry["status"] = "active"
                    entry["banned_at"] = None
                entry["last_seen"] = ts
                if entry["first_seen"] is None:
                    entry["first_seen"] = ts

    return dict(data)


def _parse_ts(ts_str: str) -> datetime:
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
