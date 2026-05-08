import glob
import json
import os

INTERESTING = {
    "cowrie.session.connect",
    "cowrie.client.version",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.closed",
    "cowrie.direct-tcpip.request",
}

LABELS = {
    "cowrie.session.connect":        ("connect",   "info"),
    "cowrie.client.version":         ("client",    "info"),
    "cowrie.login.failed":           ("auth_fail", "fail"),
    "cowrie.login.success":          ("auth_ok",   "success"),
    "cowrie.command.input":          ("cmd",       "cmd"),
    "cowrie.session.file_download":  ("download",  "danger"),
    "cowrie.session.closed":         ("closed",    "info"),
    "cowrie.direct-tcpip.request":   ("tcpip",     "info"),
}


def _cowrie_files(base: str) -> list[str]:
    """Retourne la liste ordonnée des fichiers de log Cowrie (rotated d'abord, courant en dernier)."""
    if os.path.isdir(base):
        rotated = sorted(glob.glob(os.path.join(base, "cowrie.json.*")))
        current = os.path.join(base, "cowrie.json")
        return rotated + ([current] if os.path.exists(current) else [])
    return [base] if os.path.exists(base) else []


def _iter_events(base: str):
    """Itère sur tous les events JSON de tous les fichiers cowrie."""
    for path in _cowrie_files(base):
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue


def parse_cowrie(base: str, limit: int = 300, session_id: str | None = None) -> list[dict]:
    events = []
    for e in _iter_events(base):
        eid = e.get("eventid", "")
        if eid not in INTERESTING:
            continue

        sid = e.get("session", "")[:8]
        if session_id and sid != session_id:
            continue

        label, kind = LABELS.get(eid, (eid.split(".")[-1], "info"))

        detail = ""
        if eid == "cowrie.client.version":
            detail = e.get("version", "")
        elif eid == "cowrie.direct-tcpip.request":
            detail = f"{e.get('dst_ip','')}:{e.get('dst_port','')}"

        events.append({
            "ts":       e.get("timestamp", ""),
            "src_ip":   e.get("src_ip", ""),
            "session":  sid,
            "label":    label,
            "kind":     kind,
            "username": e.get("username", ""),
            "password": e.get("password", ""),
            "input":    e.get("input", ""),
            "url":      e.get("url", ""),
            "version":  e.get("version", ""),
            "detail":   detail,
        })

    if session_id:
        return events
    return events[-limit:]


def cowrie_sessions(base: str) -> list[dict]:
    sessions: dict[str, dict] = {}

    for e in _iter_events(base):
        sid = e.get("session", "")[:8]
        if not sid:
            continue

        if sid not in sessions:
            sessions[sid] = {
                "session_id":       sid,
                "src_ip":           e.get("src_ip", ""),
                "start_time":       None,
                "end_time":         None,
                "logins_failed":    0,
                "login_ok":         False,
                "command_count":    0,
                "commands_preview": [],
                "download_count":   0,
                "status":           "active",
                "client_version":   "",
            }

        s = sessions[sid]
        ts  = e.get("timestamp", "")
        eid = e.get("eventid", "")

        if ts:
            if s["start_time"] is None or ts < s["start_time"]:
                s["start_time"] = ts
            if s["end_time"] is None or ts > s["end_time"]:
                s["end_time"] = ts

        if eid == "cowrie.client.version":
            s["client_version"] = e.get("version", "")
        elif eid == "cowrie.login.failed":
            s["logins_failed"] += 1
            if s["status"] == "active":
                s["status"] = "auth_fail"
        elif eid == "cowrie.login.success":
            s["login_ok"] = True
            s["status"] = "auth_ok"
        elif eid == "cowrie.command.input":
            s["command_count"] += 1
            cmd = e.get("input", "")
            if cmd and len(s["commands_preview"]) < 3:
                s["commands_preview"].append(cmd[:60])
        elif eid == "cowrie.session.file_download":
            s["download_count"] += 1
        elif eid == "cowrie.session.closed":
            if s["status"] not in ("auth_ok",):
                s["status"] = "closed"

    result = sorted(sessions.values(), key=lambda s: s["start_time"] or "", reverse=True)
    return result[:200]


def cowrie_summary(base: str) -> dict:
    events = parse_cowrie(base, limit=100_000)
    sessions    = {e["session"] for e in events}
    unique_ips  = {e["src_ip"] for e in events if e["src_ip"]}
    logins_ok   = sum(1 for e in events if e["kind"] == "success")
    logins_fail = sum(1 for e in events if e["kind"] == "fail")
    commands    = sum(1 for e in events if e["kind"] == "cmd")
    downloads   = sum(1 for e in events if e["kind"] == "danger")
    return {
        "enabled":     len(events) > 0,
        "sessions":    len(sessions),
        "unique_ips":  len(unique_ips),
        "logins_ok":   logins_ok,
        "logins_fail": logins_fail,
        "commands":    commands,
        "downloads":   downloads,
    }
