import asyncio
import ipaddress
import json
import os
import re
import socket
from collections import defaultdict
from datetime import datetime, timedelta

import aiohttp
from cachetools import TTLCache
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from geo import lookup as geo
from parsers.cowrie import cowrie_sessions, cowrie_summary, parse_cowrie
from parsers.fail2ban import parse_fail2ban_log
from parsers.firewall import parse_firewall_drops
from parsers.journald import classify_attack, parse_ssh_journal_file

router = APIRouter()

_cache: TTLCache = TTLCache(maxsize=16, ttl=30)
_fw_cache: TTLCache = TTLCache(maxsize=4, ttl=30)
_traceroute_cache: TTLCache = TTLCache(maxsize=32, ttl=600)
_intel_cache: TTLCache = TTLCache(maxsize=64, ttl=3600)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _parse_traceroute_output(output: str) -> list[dict]:
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("traceroute"):
            continue
        m = re.match(r'^(\d+)\s+(.*)', line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2).strip()
        if re.match(r'^[\*\s]+$', rest):
            hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None, "private": False, "geo": None})
            continue
        parts = rest.split()
        if not parts:
            continue
        hop_ip = parts[0]
        try:
            ipaddress.ip_address(hop_ip)
        except ValueError:
            continue
        rtt = None
        for i in range(1, len(parts)):
            if parts[i] == "ms":
                try:
                    rtt = float(parts[i - 1])
                    break
                except (ValueError, IndexError):
                    pass
        private = _is_private(hop_ip)
        geo_info = None
        if not private:
            g = geo.lookup(hop_ip)
            if g.get("latitude", 0) != 0 or g.get("longitude", 0) != 0:
                geo_info = g
        hops.append({"hop": hop_num, "ip": hop_ip, "rtt_ms": rtt, "private": private, "geo": geo_info})
    return hops

FAIL2BAN_LOG  = os.environ.get("FAIL2BAN_LOG",      "/host/fail2ban.log")
SSH_JOURNAL   = os.environ.get("SSH_JOURNAL_FILE",  "/host/ssh-journal.jsonl")
FIREWALL_LOG  = os.environ.get("FIREWALL_LOG",      "/host/firewall-drops.jsonl")
COWRIE_LOG    = os.environ.get("COWRIE_LOG",        "/host/cowrie.json")


def _iso(dt) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _get_merged_data() -> list[dict]:
    cache_key = "merged"
    if cache_key in _cache:
        return _cache[cache_key]

    f2b = parse_fail2ban_log(FAIL2BAN_LOG)
    journal = parse_ssh_journal_file(SSH_JOURNAL)

    all_ips = set(f2b.keys()) | set(journal.keys())
    result = []

    for ip in all_ips:
        f = f2b.get(ip, {})
        j = journal.get(ip, {})

        tried_users = j.get("tried_users", set())
        attempts = max(f.get("attempts", 0), j.get("attempts", 0))
        attack_type = classify_attack(tried_users, attempts)

        geo_info = geo.lookup(ip)

        # Merge timestamps from both sources — prefer the broader range
        f_first = f.get("first_seen")
        f_last  = f.get("last_seen")
        j_first = j.get("first_seen")
        j_last  = j.get("last_seen")

        first_seen = min(d for d in (f_first, j_first) if d) if (f_first or j_first) else None
        last_seen  = max(d for d in (f_last,  j_last)  if d) if (f_last  or j_last)  else None

        result.append({
            "ip":          ip,
            "attempts":    attempts,
            "status":      f.get("status", "active"),
            "ban_count":   f.get("ban_count", 0),
            "jail":        f.get("jail", "sshd"),
            "attack_type": attack_type,
            "tried_users": sorted(tried_users)[:10],
            "first_seen":  _iso(first_seen),
            "last_seen":   _iso(last_seen),
            "banned_at":   _iso(f.get("banned_at")),
            "events":      j.get("events", []),
            **geo_info,
        })

    result.sort(key=lambda x: x["attempts"], reverse=True)

    cowrie_ip_set = {s["src_ip"] for s in cowrie_sessions(COWRIE_LOG) if s.get("src_ip")}
    for item in result:
        item["in_honeypot"] = item["ip"] in cowrie_ip_set

    _cache[cache_key] = result
    return result


async def _get_fw_data() -> list[dict]:
    cache_key = "firewall"
    if cache_key in _fw_cache:
        return _fw_cache[cache_key]
    data = parse_firewall_drops(FIREWALL_LOG)
    _fw_cache[cache_key] = data
    return data


# ── SSH attacks ───────────────────────────────────────────────────────────────

@router.get("/attacks")
async def get_attacks(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=100, le=500),
):
    data = await _get_merged_data()
    start = (page - 1) * size
    items = [
        {k: v for k, v in item.items() if k != "events"}
        for item in data[start: start + size]
    ]
    return {"total": len(data), "page": page, "size": size, "items": items}


@router.get("/attacks/{ip}/events")
async def get_ip_events(ip: str):
    data = await _get_merged_data()
    item = next((d for d in data if d["ip"] == ip), None)
    if not item:
        raise HTTPException(status_code=404, detail="IP not found")
    events = list(reversed(item.get("events", [])))
    return {
        "ip":          ip,
        "attempts":    item["attempts"],
        "attack_type": item["attack_type"],
        "status":      item["status"],
        "events":      events,
    }


@router.get("/attacks/{ip}/traceroute")
async def get_ip_traceroute(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")

    if ip in _traceroute_cache:
        return _traceroute_cache[ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-n", "-m", "20", "-w", "2", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Traceroute timeout")
    except FileNotFoundError:
        raise HTTPException(status_code=501, detail="traceroute not available")

    hops = _parse_traceroute_output(stdout.decode(errors="replace"))
    maxlab_geo = geo.lookup("51.83.100.146")
    result = {"target_ip": ip, "maxlab_geo": maxlab_geo, "hops": hops}
    _traceroute_cache[ip] = result
    return result


def _parse_ripe_stat(data: dict) -> dict:
    d = data.get("data", {})
    asns = d.get("asns", [])
    asn_holder = asns[0].get("holder", "") if asns else ""
    resource = d.get("resource", "")
    block = d.get("block", {})
    return {
        "name": block.get("name") or resource,
        "range": resource,
        "cidr": resource if "/" in resource else None,
        "country": None,
        "org": asn_holder or None,
        "abuse_email": None,
        "registered": None,
    }


@router.get("/attacks/{ip}/intel")
async def get_ip_intel(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")

    if ip in _intel_cache:
        return _intel_cache[ip]

    # Reverse DNS
    rdns = None
    try:
        loop = asyncio.get_event_loop()
        host_info = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=5
        )
        rdns = host_info[0]
    except Exception:
        pass

    # Network info: RIPE stat (free, no auth, no Cloudflare block)
    rdap = None
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.get(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
            ) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    rdap = _parse_ripe_stat(raw)
                    # Enrich with ipinfo for country
                    async with session.get(f"https://ipinfo.io/{ip}/json") as resp2:
                        if resp2.status == 200:
                            info = await resp2.json(content_type=None)
                            if rdap:
                                rdap["country"] = info.get("country")
                                if not rdap.get("org"):
                                    rdap["org"] = info.get("org")
    except Exception:
        pass

    # Honeypot correlation
    sessions = cowrie_sessions(COWRIE_LOG)
    ip_sessions = [s for s in sessions if s.get("src_ip") == ip]
    honeypot = {
        "seen": len(ip_sessions) > 0,
        "sessions": len(ip_sessions),
        "auth_ok": sum(1 for s in ip_sessions if s.get("login_ok")),
        "commands": [c for s in ip_sessions for c in (s.get("commands_preview") or [])],
        "first_seen": min((s["start_time"] for s in ip_sessions if s.get("start_time")), default=None),
        "last_seen":  max((s["end_time"]   for s in ip_sessions if s.get("end_time")),   default=None),
    }

    result = {"ip": ip, "rdns": rdns, "rdap": rdap, "honeypot": honeypot}
    _intel_cache[ip] = result
    return result


@router.get("/stats/usernames")
async def get_usernames():
    journal = parse_ssh_journal_file(SSH_JOURNAL)
    counts: dict[str, int] = defaultdict(int)
    for entry in journal.values():
        for user in entry.get("tried_users", set()):
            counts[user] += 1
    result = [{"username": u, "count": c} for u, c in counts.items()]
    return sorted(result, key=lambda x: x["count"], reverse=True)[:50]


@router.get("/stats/campaigns")
async def get_campaigns():
    data = await _get_merged_data()
    by_subnet: dict[str, list] = defaultdict(list)
    for item in data:
        parts = item["ip"].split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            by_subnet[subnet].append(item)
    campaigns = [
        {
            "subnet":         subnet,
            "ip_count":       len(ips),
            "total_attempts": sum(i["attempts"] for i in ips),
            "country_name":   ips[0].get("country_name", "Unknown"),
            "flag":           ips[0].get("flag", "🏴"),
            "org":            ips[0].get("org") or "—",
            "preview_ips":    [i["ip"] for i in ips[:5]],
        }
        for subnet, ips in by_subnet.items()
        if len(ips) >= 2
    ]
    return sorted(campaigns, key=lambda x: x["ip_count"], reverse=True)[:20]


@router.get("/stats/countries")
async def get_countries():
    data = await _get_merged_data()
    by_country: dict[str, dict] = defaultdict(lambda: {
        "attack_count": 0,
        "ip_count":     0,
        "top_ips":      [],
    })

    for item in data:
        cc = item["country_code"]
        entry = by_country[cc]
        entry["country_code"] = cc
        entry["country_name"] = item["country_name"]
        entry["flag"]         = item["flag"]
        entry["latitude"]     = item["latitude"]
        entry["longitude"]    = item["longitude"]
        entry["attack_count"] += item["attempts"]
        entry["ip_count"]     += 1
        if len(entry["top_ips"]) < 3:
            entry["top_ips"].append(item["ip"])

    return sorted(by_country.values(), key=lambda x: x["attack_count"], reverse=True)


@router.get("/stats/timeline")
async def get_timeline():
    data = await _get_merged_data()
    buckets: dict[str, int] = defaultdict(int)
    now = datetime.utcnow()
    cutoff = now - timedelta(days=7)

    for item in data:
        for ts_field in ("last_seen", "first_seen"):
            ts_str = item.get(ts_field)
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.rstrip("Z"))
                    if ts >= cutoff:
                        hour_key = ts.strftime("%Y-%m-%dT%H:00")
                        buckets[hour_key] += item["attempts"]
                        break
                except ValueError:
                    pass

    sorted_buckets = sorted(buckets.items())
    return [{"timestamp": k, "count": v} for k, v in sorted_buckets]


@router.get("/stats/summary")
async def get_summary():
    data = await _get_merged_data()
    fw   = await _get_fw_data()

    banned = sum(1 for d in data if d["status"] == "banned")
    total_attempts = sum(d["attempts"] for d in data)

    # IPs uniques SSH
    ssh_ips = {d["ip"] for d in data}
    ssh_countries = {d["country_code"] for d in data if d["country_code"] != "XX"}

    # IPs uniques firewall + pays (geo lookup depuis le cache)
    fw_ips = {e["ip"] for e in fw}
    fw_countries: set[str] = set()
    # Agréger aussi les drops par pays pour le top country combiné
    combined_country_hits: dict[str, dict] = defaultdict(lambda: {"count": 0, "name": "", "flag": ""})
    for d in data:
        cc = d["country_code"]
        if cc != "XX":
            fw_countries  # (pas fw_countries ici, c'est ssh)
            combined_country_hits[cc]["count"] += d["attempts"]
            combined_country_hits[cc]["name"]   = d["country_name"]
            combined_country_hits[cc]["flag"]   = d["flag"]
    for e in fw:
        g = geo.lookup(e["ip"])
        cc = g["country_code"]
        if cc != "XX":
            fw_countries.add(cc)
            combined_country_hits[cc]["count"] += 1
            combined_country_hits[cc]["name"]   = g["country_name"]
            combined_country_hits[cc]["flag"]   = g["flag"]

    top_cc = max(combined_country_hits.items(), key=lambda x: x[1]["count"], default=(None, {}))
    top_entry = top_cc[1] if top_cc[0] else {}

    return {
        "total_ips":        len(ssh_ips | fw_ips),
        "ssh_ips":          len(ssh_ips),
        "fw_ips":           len(fw_ips),
        "banned_count":     banned,
        "active_count":     len(data) - banned,
        "countries_count":  len(ssh_countries | fw_countries),
        "total_attempts":   total_attempts,
        "top_country":      top_entry.get("name"),
        "top_country_flag": top_entry.get("flag"),
        "last_updated":     datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ── Firewall drops ────────────────────────────────────────────────────────────

@router.get("/firewall/summary")
async def get_firewall_summary():
    events = await _get_fw_data()
    unique_ips   = {e["ip"]  for e in events}
    unique_ports = {e["dpt"] for e in events if e["dpt"]}
    return {
        "total_drops":  len(events),
        "unique_ips":   len(unique_ips),
        "unique_ports": len(unique_ports),
        "enabled":      len(events) > 0,
    }


@router.get("/firewall/ports")
async def get_firewall_ports():
    events = await _get_fw_data()
    by_port: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "ips": set()})

    for e in events:
        key = (e["dpt"], e["proto"], e["service"])
        by_port[key]["count"] += 1
        by_port[key]["ips"].add(e["ip"])

    result = [
        {
            "port":       k[0],
            "proto":      k[1],
            "service":    k[2],
            "count":      v["count"],
            "unique_ips": len(v["ips"]),
        }
        for k, v in by_port.items()
    ]
    result.sort(key=lambda x: x["count"], reverse=True)
    return result[:20]


@router.get("/firewall/recent")
async def get_firewall_recent(limit: int = Query(default=100, le=500)):
    events = await _get_fw_data()
    recent = sorted(events, key=lambda x: x["ts"] or "", reverse=True)[:limit]
    result = []
    for e in recent:
        g = geo.lookup(e["ip"])
        result.append({**e, "flag": g["flag"], "country_code": g["country_code"], "country_name": g["country_name"]})
    return result


# ── Honeypot Cowrie ───────────────────────────────────────────────────────────

@router.get("/cowrie/summary")
async def get_cowrie_summary():
    return cowrie_summary(COWRIE_LOG)


@router.get("/cowrie/sessions")
async def get_cowrie_sessions_list():
    return cowrie_sessions(COWRIE_LOG)


@router.get("/cowrie/sessions/{session_id}")
async def get_cowrie_session_events(session_id: str):
    if not session_id.isalnum() or len(session_id) > 16:
        raise HTTPException(status_code=400, detail="Invalid session ID")
    return parse_cowrie(COWRIE_LOG, limit=1000, session_id=session_id)


@router.get("/cowrie/events")
async def get_cowrie_events(limit: int = Query(default=200, le=500)):
    return parse_cowrie(COWRIE_LOG, limit=limit)


def _cowrie_current_file() -> str:
    """Retourne le fichier cowrie.json courant (chemin direct ou dans le dossier)."""
    if os.path.isdir(COWRIE_LOG):
        return os.path.join(COWRIE_LOG, "cowrie.json")
    return COWRIE_LOG


@router.get("/cowrie/stream")
async def cowrie_stream(request: Request):
    async def generator():
        live = _cowrie_current_file()
        pos = os.path.getsize(live) if os.path.exists(live) else 0
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            if await request.is_disconnected():
                break
            live = _cowrie_current_file()
            if not os.path.exists(live):
                await asyncio.sleep(1)
                continue
            size = os.path.getsize(live)
            if size > pos:
                with open(live, "r", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                pos = size
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        eid = e.get("eventid", "")
                        if eid in {
                            "cowrie.session.connect", "cowrie.client.version",
                            "cowrie.login.failed",
                            "cowrie.login.success", "cowrie.command.input",
                            "cowrie.session.file_download", "cowrie.session.closed",
                        }:
                            yield f"data: {json.dumps(e)}\n\n"
                    except json.JSONDecodeError:
                        pass
            await asyncio.sleep(0.8)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
